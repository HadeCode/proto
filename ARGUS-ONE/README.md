# ARGUS-ONE

The FastAPI backend streams validated flow metadata into the detector defined
in the sibling `../argus_one.py` module. It does not generate traffic or
inspect packet payloads.

## Run the API

From this directory:

```powershell
py -3.13 -m pip install -r requirements.txt
py -3.13 -m uvicorn backend.main:app --reload
```

Submit normalized flow metadata to `POST /api/flows`. The response contains
the structured alerts returned by `ArgusOneDetector`; an empty `alerts` array
means no detector threshold was met for that flow.

Use `POST /api/flows/batch` to replay an ordered list of metadata records.
To exercise all nine built-in detection scenarios, keep the API running and
run `py -3.13 test_all_attacks.py` from the parent `work` directory.
