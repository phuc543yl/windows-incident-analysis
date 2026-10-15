"""Create persistent synthetic Crow-Eye cases through the project's own services.
No network requests, Windows collection, task creation, or service changes.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import traceback

BUNDLE = Path(__file__).resolve().parent
REQUIRED = {'failed_logon_burst', 'successful_logon_after_failures',
            'suspicious_powershell', 'scheduled_task_created',
            'service_configuration_changed', 'file_integrity_change',
            'connection_flood', 'service_probe_failed'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def check_root(root):
    for name in ('case_management/case_service.py', 'analysis/analysis_service.py',
                 'processing/processing_pipeline.py', 'config/detection_rules.json',
                 'config/investigation_profiles/general_investigation.json'):
        if not (root / name).is_file():
            raise ValueError(f'Not a supported Crow-Eye root: missing {name}\nUse --root with the project directory.')
    enabled = {r['id'] for r in read(root/'config/detection_rules.json')['rules'] if r.get('enabled', True)}
    profile = set(read(root/'config/investigation_profiles/general_investigation.json')['detection_rules'])
    missing = REQUIRED - (enabled & profile)
    if missing:
        raise ValueError('Version/profile mismatch. Missing enabled rules: '+', '.join(sorted(missing))+
                         '\nThis bundle targets windows-incident-analysis, commit 9861df6. No Case was created.')


def load_scenario(name):
    scenario = read(BUNDLE/'data'/f'{name}.json')
    if not scenario.get('synthetic') or not scenario.get('records'):
        raise ValueError('Invalid synthetic scenario file.')
    # Preserve relative gaps while moving the whole scenario to a recent UTC time.
    rows = scenario['records']
    original = [datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')) for r in rows]
    end = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=2)
    shift = end - max(original)
    for row, timestamp in zip(rows, original):
        row['timestamp'] = (timestamp+shift).isoformat(timespec='milliseconds').replace('+00:00','Z')
    return scenario


def run_case(root, scenario, prepare_only):
    from case_management.case_service import CaseService
    from processing.processing_pipeline import ProcessingPipeline
    from analysis.analysis_service import AnalysisService
    from evidence.evidence_service import EvidenceService
    from common.json_utils import write_json
    from analysis.investigation.baseline import BaselineComparer

    name = scenario['scenario_id']
    service = CaseService(root, actor='synthetic-sample-runner')
    case = service.create_case(
        title=scenario['title'], target_hostname=scenario['target_hostname'],
        target_ip_addresses=('192.0.2.20',), profile_id=scenario['profile_id'],
        description='SYNTHETIC FIXTURE. Not collected from Windows. Tests normalization/detection/correlation only. Do not run raw acquisition processing on this fixture Case.',
        hypothesis='Synthetic training case; expected behavior is defined in fixture_records.json.',
        tags=('synthetic', 'sample-test', name))
    print(f'CREATED {case.case_id} | {name}', flush=True)
    paths = service.repository.paths(case.case_id)
    try:
        service.update_case(case.case_id, metadata={'synthetic': True, 'sample_scenario': name,
                            'tested_reference_commit': '9861df66fb81dd41103e864c5634133449154184'})
        folder = paths.raw/'Files'
        folder.mkdir(parents=True, exist_ok=True)
        write_json(folder/'fixture_records.json', scenario)
        (folder/'SYNTHETIC_NOTICE.txt').write_text(
            'All input records and sample files are synthetic. No EVTX was captured.\n'
            'Hash verification checks these fixture files only. No real attack occurred.\n', encoding='utf-8')
        (folder/'tracked_before.txt').write_bytes((BUNDLE/'data'/'tracked_before.txt').read_bytes())
        after = 'tracked_after.txt' if name == 'full' else 'tracked_before.txt'
        (folder/'tracked_after.txt').write_bytes((BUNDLE/'data'/after).read_bytes())
        evidence = EvidenceService(root, actor='synthetic-sample-runner')
        evidence.preserve_case(case.case_id)
        verify = evidence.verify_case(case.case_id)
        pipeline = ProcessingPipeline(root, actor='synthetic-sample-runner')
        processed = pipeline.process(case_id=case.case_id, records=scenario['records'])
        # Check the persisted artifacts, not merely the objects returned in memory.
        records = pipeline.load_records(case.case_id)
        timeline = pipeline.load_timeline(case.case_id)
        baseline = BaselineComparer(root).compare(case.case_id, records)
        base_checks = {
            'normalized_count': len(records) == len(scenario['records']),
            'timeline_count': len(timeline) == len(records),
            'source_references_exist': all((paths.root/r.raw_reference).is_file() for r in records),
            'baseline_changed_as_expected': (baseline.change_count > 0) == (name == 'full'),
        }
        result = {'synthetic':True, 'scenario_id':name, 'case_id':case.case_id,
                  'case_path':str(paths.root), 'record_count':len(records),
                  'timeline_count':len(timeline), 'utc_start':min(r.timestamp for r in records).isoformat(),
                  'utc_end':max(r.timestamp for r in records).isoformat(),
                  'evidence_verification':verify, 'baseline_change_count':baseline.change_count,
                  'expected':scenario['expected'], 'checks':base_checks}
        if prepare_only:
            result['status'] = 'PREPARED' if all(base_checks.values()) else 'FAIL'
        else:
            analyzer = AnalysisService(root, actor='synthetic-sample-runner')
            analyzer.analyze(case_id=case.case_id)
            alerts = analyzer.load_alerts(case.case_id)
            incidents = analyzer.load_incidents(case.case_id)
            actual_rules = sorted({a.rule_id for a in alerts})
            actual_types = sorted({i.details.get('incident_type') for i in incidents})
            expected = scenario['expected']
            known_ids = {r.record_id for r in records}
            base_checks.update({
                'rule_ids':actual_rules == sorted(expected['rule_ids']),
                'alert_count':len(alerts) == expected['alert_count'],
                'incident_types':actual_types == sorted(expected['incident_types']),
                'incident_count':len(incidents) == expected['incident_count'],
                'incidents_suspected':all(i.status.value == 'suspected' for i in incidents),
                'no_confirmed_cia':all(not i.cia_impacts for i in incidents),
                'alert_record_links':all(a.source_record_ids and set(a.source_record_ids)<=known_ids for a in alerts),
            })
            result.update(actual_rule_ids=actual_rules, actual_incident_types=actual_types,
                          alert_count=len(alerts), incident_count=len(incidents),
                          alerts_by_rule=dict(Counter(a.rule_id for a in alerts)),
                          status='PASS' if all(base_checks.values()) else 'FAIL')
        destination = paths.root/'sample_test_result.json'
        write_json(destination, result)
        print(f"{result['status']} | records={len(records)} | alerts={result.get('alert_count','not run')} | incidents={result.get('incident_count','not run')}")
        for label, passed in base_checks.items():
            if not passed: print('  FAILED CHECK:',label)
        print('CASE:',paths.root)
        print('RESULT:',destination)
        print('UTC:',result['utc_start'],'to',result['utc_end'])
        return result
    except Exception as exc:
        write_json(paths.root/'sample_test_error.json', {'synthetic':True,'case_id':case.case_id,'error':str(exc),'traceback':traceback.format_exc()})
        print('Incomplete sample Case retained for diagnosis:',paths.root, file=sys.stderr)
        raise


def main():
    parser=argparse.ArgumentParser(description='Create synthetic sample Cases with the real Crow-Eye pipeline.')
    parser.add_argument('--root',type=Path,default=Path.cwd(),help='Crow-Eye project root; default current directory')
    parser.add_argument('--scenario',choices=['all','full','normal'],default='all')
    parser.add_argument('--prepare-only',action='store_true',help='Create/normalize Cases; run analysis manually in GUI')
    args=parser.parse_args()
    root=args.root.expanduser().resolve()
    check_root(root)  # Validate before creating any Case.
    sys.path.insert(0,str(root))
    scenarios=[load_scenario(n) for n in (['full','normal'] if args.scenario=='all' else [args.scenario])]
    print('SYNTHETIC SAMPLE TEST - no live collection or attack is executed.')
    print('Each run creates new Cases; existing Cases and rules are not modified.')
    results=[run_case(root,s,args.prepare_only) for s in scenarios]
    print('Open the printed CASE IDs in Crow-Eye. Do not click "1. Xu ly du lieu tho" for these fixture Cases.')
    return 1 if any(r['status']=='FAIL' for r in results) else 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('ERROR:',error,file=sys.stderr)
        raise SystemExit(2)
