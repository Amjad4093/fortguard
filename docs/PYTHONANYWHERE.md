# FortGuard test server on PythonAnywhere (free, no card)

About 15 minutes, once. Everything is clicks plus two commands to paste.

## 1. Create the account

1. Go to **pythonanywhere.com** → **Pricing & signup** → **Create a Beginner account** (free, no card).
2. Your username becomes your address: `https://<username>.pythonanywhere.com`.

## 2. Create the web app

1. Open the **Web** tab → **Add a new web app** → **Next**.
2. Choose **Manual configuration** (not Flask) → **Python 3.12** → **Next**.
   If 3.12 is not offered, pick 3.13 or 3.11 and use that number in step 4 too.

## 3. Upload the code

1. Open the **Files** tab. You are in `/home/<username>/`.
2. **Upload a file** → choose `fortguard-pythonanywhere.zip`.

## 4. Run the setup (paste two lines)

1. Open the **Consoles** tab → **Bash**.
2. Paste:

   ```bash
   unzip -o -q fortguard-pythonanywhere.zip
   python3.12 fortguard/deploy/pythonanywhere_setup.py
   ```

3. It installs what is needed, checks itself, and prints your **admin password** and **API key**.
   Keep them private. To see them again later: `cat ~/.fortguard-secrets`.

## 5. Switch it on

1. Back on the **Web** tab, turn on **Force HTTPS** (Security section).
2. Press the green **Reload** button.
3. Open `https://<username>.pythonanywhere.com/portal` and sign in as `admin`.
   Press **Run sample scenarios** on the Dashboard to see example cases.

## Use it

| What | Where |
|---|---|
| Back office | `https://<username>.pythonanywhere.com/portal` (user `admin`) |
| Android app | open FortGuardDemo.apk, Server `https://<username>.pythonanywhere.com`, paste the API key, **Connect** |
| Any phone's browser | `https://<username>.pythonanywhere.com/phone` |

## Keep it running

Free web apps stop after **one month** unless extended: on the **Web** tab press
**Run until 1 month from today**. PythonAnywhere emails a reminder.

## Update to a newer version

Upload the new `fortguard-pythonanywhere.zip`, then in a Bash console:

```bash
unzip -o -q fortguard-pythonanywhere.zip
python3.12 fortguard/deploy/pythonanywhere_setup.py
```

and press **Reload**. Your secrets, cases and users are kept.

## If something goes wrong

- **Web tab → Log files → Error log**: the last lines say what failed. Send them to Claude.
- "No web app found" from the script: do step 2 first.
- The site shows "Something went wrong": check the error log, then press Reload.

## Limits of the free plan

One web app, one worker, 512 MB disk, the one-month renewal above. Fine for testing with a few phones;
not for real customers. Everything runs in dev mode: device attestation is simulated and data is
synthetic.
