# Supabase Exposure Check

A Python script to check for exposed Supabase tables by enumerating all REST-exposed tables, testing whether each table was readable, and safely dumping readable data as JSON (read-only).

Related blog post: [How rep+ Helped Me Identify a Critical Supabase JWT Exposure]([https://bour.ch/blog](https://bour.ch/how-rep-helped-me-identify-a-critical-supabase-jwt-exposure/))

## Setup

First, export the required environment variables:

```bash
export SUPABASE_URL=https://xxxx.supabase.co
export SUPABASE_APIKEY=ANON_KEY
export SUPABASE_JWT=JWT_TOKEN
```

## Usage

Run the script:

```bash
python supabase-exposure-check.py
```

The script will:
1. Enumerate all REST-exposed tables
2. Test whether each table was readable
3. Safely dump readable data as JSON (read-only)

Output is saved to the `dump/` directory (one JSON file per table), along with a `_summary.json` file containing the results.

## Example Output

```bash
python3 supabase-exposure-check.py 
[*] Enumerating exposed tables...
[+] Found 34 tables

[*] Dumping table: m█████████s
    [+] Dumped 38180 rows → dump/m█████████s.json
[*] Dumping table: a██s
    [+] Dumped 2168 rows → dump/a██s.json
[*] Dumping table: s██e██ed_██sts
    [+] Dumped 792 rows → dump/s██e██ed_██sts.json
[*] Dumping table: i████tions
    [+] Dumped 0 rows → dump/i████tions.json
[*] Dumping table: product_██ases
    [+] Dumped 9938 rows → dump/product_██ases.json
[*] Dumping table: us██_age
    [+] Dumped 0 rows → dump/us██_age.json
[*] Dumping table: user_████s██_access
```

## Command-line Options

You can also provide the configuration via command-line arguments instead of environment variables:

```bash
python supabase-exposure-check.py --url https://xxxx.supabase.co --apikey ANON_KEY --jwt JWT_TOKEN
```

Additional options:
- `--out`: Output directory (default: `dump`)
- `--page-size`: Number of rows per page (default: `1000`)

## Output

The script creates:
- Individual JSON files for each readable table in the `dump/` directory
- A `_summary.json` file with a summary of all tested tables and their accessibility status
