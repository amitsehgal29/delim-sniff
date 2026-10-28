# delim-sniff

Check the raw format of a delimited file before you load it. Standard-library Python only.

It reports the encoding guess (utf-8, utf-8-sig, utf-16, latin-1), BOM, line endings (LF, CRLF, CR or mixed), delimiter (`,` `;` tab `|`), quote char, header guess, row count and whether rows have uneven field counts.

```
python delim_sniff.py landing/orders.csv
```

Exits 1 when rows are ragged, so it can gate a pipeline step.

Run tests: `python -m unittest -v`
