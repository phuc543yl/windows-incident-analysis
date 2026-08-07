# TÃ­ch há»£p cÃ´ng cá»¥ DFIR

## 1. Má»¥c tiÃªu

ThÆ° má»¥c `integrations/` bao bá»c cÃ¡c cÃ´ng cá»¥ DFIR bÃªn ngoÃ i báº±ng ba há»£p Ä‘á»“ng:

1. `ToolRegistry` Ä‘á»c vÃ  kiá»ƒm tra definition trong
   `config/tool_integrations.json`;
2. adapter xÃ¢y argument cá»‘ Ä‘á»‹nh tá»« input Ä‘Ã£ xÃ¡c thá»±c vÃ  gá»i `ToolRunner`;
3. parser chuyá»ƒn CSV/JSON/JSONL thÃ nh `NormalizedRecord`.

Executable khÃ´ng Ä‘Æ°á»£c commit vÃ o Git. NgÆ°á»i triá»ƒn khai tá»± Ä‘áº·t binary há»£p phÃ¡p
vÃ o Ä‘Ãºng vá»‹ trÃ­ dÆ°á»›i `tools/`.

## 2. Danh sÃ¡ch tÃ­ch há»£p

| Tool ID | Artifact | Adapter/parser | Output | Timeout | Vá»‹ trÃ­ executable |
|---|---|---|---|---:|---|
| `hayabusa` | `event_logs` | `hayabusa` | CSV | 300 s | `tools/Hayabusa/hayabusa.exe` |
| `evtxecmd` | `event_logs` | `evtxecmd` | CSV | 300 s | `tools/EZTools/net9/EvtxeCmd/EvtxECmd.exe` |
| `pecmd` | `prefetch` | `pecmd` | CSV | 180 s | `tools/EZTools/net9/PECmd.exe` |
| `amcacheparser` | `amcache` | `amcacheparser` | CSV | 180 s | `tools/EZTools/net9/AmcacheParser.exe` |
| `mftecmd` | `mft` | `mftecmd` | CSV | 300 s | `tools/EZTools/net9/MFTECmd.exe` |
| `recmd` | `registry` | `recmd` | CSV | 300 s | `tools/EZTools/net9/RECmd/RECmd.exe` |

Hayabusa vÃ  EvtxECmd lÃ  hai tool báº¯t buá»™c cho MVP theo cáº¥u hÃ¬nh hiá»‡n táº¡i. CÃ¡c
tool cÃ²n láº¡i phá»¥c vá»¥ Ä‘iá»u tra persistence vÃ  file-system artifact.

## 3. Definition cáº¥u hÃ¬nh

Má»—i pháº§n tá»­ trong `tools` cÃ³ schema:

```json
{
  "id": "evtxecmd",
  "name": "EvtxECmd",
  "enabled": true,
  "required_for_mvp": true,
  "adapter": "evtxecmd",
  "executable": "tools/EZTools/net9/EvtxeCmd/EvtxECmd.exe",
  "supported_artifacts": [
    "event_logs"
  ],
  "output_format": "csv",
  "timeout_seconds": 300
}
```

Quy táº¯c:

- `id` vÃ  `adapter` lÃ  chá»¯ thÆ°á»ng, báº¯t Ä‘áº§u báº±ng chá»¯ cÃ¡i;
- `executable` lÃ  Ä‘Æ°á»ng dáº«n tÆ°Æ¡ng Ä‘á»‘i an toÃ n báº¯t Ä‘áº§u báº±ng `tools/`;
- format chá»‰ lÃ  `csv`, `json` hoáº·c `jsonl`;
- `supported_artifacts` khÃ´ng rá»—ng vÃ  dÃ¹ng giÃ¡ trá»‹ `ArtifactType`;
- timeout lÃ  sá»‘ dÆ°Æ¡ng;
- ID khÃ´ng Ä‘Æ°á»£c trÃ¹ng;
- `enabled: false` ngÄƒn tool cháº¡y dÃ¹ executable tá»“n táº¡i.

## 4. Kiá»ƒm tra trÆ°á»›c khi cháº¡y

`ToolValidator` xÃ¡c nháº­n:

- executable náº±m dÆ°á»›i thÆ° má»¥c `tools/`;
- path tá»“n táº¡i vÃ  lÃ  file;
- executable khÃ´ng pháº£i symbolic link;
- tráº¡ng thÃ¡i enable Ä‘Æ°á»£c pháº£n Ã¡nh thÃ nh warning hoáº·c lá»—i khi yÃªu cáº§u cháº¡y.

Kiá»ƒm tra trong Python:

```python
from integrations.tool_registry import ToolRegistry
from integrations.tool_validator import ToolValidator

registry = ToolRegistry()
for result in ToolValidator(registry).validate_all():
    print(result.to_dict())
```

Thiáº¿u binary lÃ  lá»—i triá»ƒn khai, khÃ´ng Ä‘Æ°á»£c kháº¯c phá»¥c báº±ng cÃ¡ch thay executable
thÃ nh má»™t Ä‘Æ°á»ng dáº«n ngoÃ i `tools/`.

## 5. Luá»“ng adapter vÃ  parser

```mermaid
flowchart TD
    A["Raw artifact trong Case"] --> B["Adapter kiá»ƒm tra input"]
    B --> C["ToolRunner cháº¡y shell=False"]
    C --> D["CSV vÃ  stdout/stderr"]
    D --> E["Parser táº¡o NormalizedRecord"]
    E --> F["Processing vÃ  analysis"]
```

Má»—i láº§n cháº¡y cÃ³ thÆ° má»¥c riÃªng:

```text
analysis/tool_outputs/<tool_id>/<run_id>/
â”œâ”€â”€ <tool-output>.csv
â”œâ”€â”€ stdout.txt
â””â”€â”€ stderr.txt
```

`logs/tool_runs.log` ghi `ToolResult`, gá»“m command, thá»i gian, exit code,
status, output file vÃ  lá»—i rÃºt gá»n. Output pháº£i náº±m trong run directory; symlink
vÃ  output thoÃ¡t khá»i Case bá»‹ tá»« chá»‘i.

## 6. Há»£p Ä‘á»“ng input vÃ  lá»‡nh

| Tool | Input | Argument chÃ­nh do adapter dá»±ng |
|---|---|---|
| Hayabusa | Má»™t thÆ° má»¥c EVTX | `csv-timeline -d <dir> -o <csv> --UTC` |
| EvtxECmd | Má»™t file hoáº·c thÆ° má»¥c EVTX | `-f/-d <input> --csv <dir> --csvf evtxecmd.csv` |
| PECmd | Má»™t file hoáº·c thÆ° má»¥c Prefetch | `-f/-d <input> --csv <dir> --csvf pecmd.csv` |
| AmcacheParser | Má»™t file `Amcache.hve` | `-f <file> --csv <dir> --csvf amcache.csv` |
| MFTECmd | Má»™t file `$MFT` | `-f <file> --csv <dir> --csvf mftecmd.csv` |
| RECmd | Má»™t file hoáº·c thÆ° má»¥c Registry hive | `-f/-d <input> --csv <dir> --csvf recmd.csv` |

Adapter nháº­n Ä‘Æ°á»ng dáº«n Ä‘Ã£ resolve, khÃ´ng nháº­n chuá»—i command hoÃ n chá»‰nh tá»« UI.
`ToolRunner` gá»i `subprocess.run` vá»›i `shell=False`, timeout theo definition vÃ 
decode output báº±ng UTF-8 vá»›i kÃ½ tá»± lá»—i Ä‘Æ°á»£c thay tháº¿.

## 7. Ãnh xáº¡ parser

| Parser | `source_type` | Timestamp Æ°u tiÃªn | Thá»±c thá»ƒ chÃ­nh |
|---|---|---|---|
| Hayabusa | `hayabusa_event` | Timestamp/Datetime/TimeCreated | event, user, process, IP |
| EvtxECmd | `evtxecmd_event` | TimeCreated/Timestamp/DateTime | event ID, user, process ID |
| PECmd | `pecmd_prefetch` | LastRun/LastRun0/SourceCreated | executable, file path |
| AmcacheParser | `amcacheparser_file` | file/key last-write | program/file path |
| MFTECmd | `mftecmd_file` | MFT modified/created | file path |
| RECmd | `recmd_registry` | Registry last-write | key/value path |

Parser giá»¯ toÃ n bá»™ row nguá»“n trong `attributes`, Ä‘á»“ng thá»i chá»n cÃ¡c trÆ°á»ng
chung cho detection vÃ  correlation. `raw_reference` luÃ´n trá» vá» output tÆ°Æ¡ng
Ä‘á»‘i trong Case.

## 8. Quan há»‡ vá»›i investigation profile

| Profile | Tool chÃ­nh |
|---|---|
| `account_compromise` | Hayabusa, EvtxECmd |
| `endpoint_compromise` | Hayabusa, EvtxECmd, PECmd, AmcacheParser, MFTECmd, RECmd |
| `log_tampering` | Hayabusa, EvtxECmd, PECmd |
| `service_disruption` | Hayabusa, EvtxECmd, RECmd, PECmd |
| `general_investigation` | Hayabusa, EvtxECmd, PECmd, AmcacheParser, RECmd |

Tool trong profile mÃ´ táº£ pipeline mong muá»‘n; `ToolValidator` váº«n pháº£i xÃ¡c nháº­n
binary táº¡i thá»i gian cháº¡y.

## 9. ThÃªm má»™t tÃ­ch há»£p má»›i

1. ThÃªm definition cÃ³ `schema_version` tÆ°Æ¡ng thÃ­ch vÃ o
   `config/tool_integrations.json`.
2. Táº¡o adapter káº¿ thá»«a `BaseAdapter`; cá»‘ Ä‘á»‹nh artifact type, kiá»ƒm tra input vÃ 
   output glob.
3. Táº¡o parser káº¿ thá»«a `BaseParser`; Ã¡nh xáº¡ row sang `NormalizedRecord`.
4. ÄÄƒng kÃ½ adapter/parser táº¡i nÆ¡i Ä‘iá»u phá»‘i tÃ­ch há»£p.
5. ThÃªm fixture nhá», vÃ´ háº¡i; khÃ´ng commit artifact nháº¡y cáº£m hay binary.
6. Viáº¿t test cho definition, command, timeout, path traversal, parse row vÃ 
   workflow end-to-end.
7. Cáº­p nháº­t investigation profile vÃ  tÃ i liá»‡u nÃ y.

## 10. Xá»­ lÃ½ lá»—i

- Exit code khÃ¡c `0`: `ToolRunStatus.FAILED`.
- VÆ°á»£t timeout: `ToolRunStatus.TIMED_OUT`.
- KhÃ´ng táº¡o output khá»›p glob: tháº¥t báº¡i dÃ¹ exit code báº±ng `0`.
- stdout/stderr luÃ´n Ä‘Æ°á»£c lÆ°u Ä‘á»ƒ Ä‘iá»u tra lá»—i, nhÆ°ng khÃ´ng thay tháº¿ evidence.
- Parser tá»« chá»‘i file format khÃ´ng há»— trá»£ hoáº·c timestamp báº¯t buá»™c bá»‹ thiáº¿u.
- Má»™t tool tháº¥t báº¡i khÃ´ng lÃ m thay Ä‘á»•i hash cá»§a raw artifact.

