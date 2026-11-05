# Circle Video Sender

Invite-only Flask website for sending MP4/3GP videos through Twilio WhatsApp.

## Browser-first setup (no local coding tools required)
1. Extract the ZIP on your computer.
2. Create a private GitHub repository and upload the project files (not the ZIP itself).
3. Deploy the repository to a Python host that supports a persistent disk.
4. Attach a persistent disk mounted at `/var/data`. Set `DATA_DIR=/var/data` and `ENABLE_CLEANUP_THREAD=true` in the host's environment settings. The app runs its own cleanup task every five minutes on its single web worker, so no separate cron service is needed.
5. Set the environment variables listed in `.env.example` in the host dashboard. Never upload `.env` or publish Twilio credentials.
6. Set `APP_BASE_URL` to the deployed public HTTPS address and `SESSION_COOKIE_SECURE=true`.
7. Set the start command to `gunicorn --workers 1 --threads 4 app:app`.
8. Open the host's shell/console and run `flask --app app create-admin` once to create the administrator.
9. Sign in, visit `/admin`, and create one-time invitation links for members.

A temporary filesystem can erase the database and videos when the app restarts or redeploys. Keep one web worker while using the built-in cleanup thread and SQLite.

## Production requirements
Deploy behind HTTPS and a production WSGI server. Set SESSION_COOKIE_SECURE=true. Use persistent storage for `circle.db` and `uploads/`. The built-in cleanup thread runs every five minutes: final-status uploads are deleted one hour after the final Twilio callback; stuck jobs are deleted after 24 hours. Configure a persistent Redis rate-limit backend for multi-worker deployments. Validate webhook URL behavior behind your hosting proxy.

Twilio needs public access to each long-random-token media URL. The message record is created before Twilio is called, so an early media fetch or status callback can be matched to the correct job. Status callbacks use a per-job URL and are signature-validated. Anyone who obtains a media URL can fetch the video until deletion, so never share it. The starter's 16 MB limit is conservative; verify your current account/media limits. WhatsApp may process media, so byte-for-byte original quality is not guaranteed. Only send videos to recipients who expect them. This is a starter, not a security audit; test before inviting members.
