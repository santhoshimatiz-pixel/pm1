iMatiz PM Tool
==============

FILES
  server.py          the app server (Python, PostgreSQL)
  index.html         the whole web page (all dashboards)
  ai_assistant.py    floating AI chat: answers from each login's own dashboard data + reminders
  help_assistant.py  Help guide answers + the fixed "only about this PM tool" replies
  seed_demo_data.py  optional: fills an empty database with demo clients and team members
  requirements.txt, Procfile, render.yaml   deployment (Render)

RUN LOCALLY
  pip install -r requirements.txt
  create a .env file next to server.py with at least:
      DATABASE_URL=postgresql://user:password@localhost:5432/matiz
      INITIAL_ADMIN_PASSWORD=<8+ characters, first run only>
  python server.py          then open http://localhost:8000
  (optional demo data:  python seed_demo_data.py)

DEPLOY (Render)
  render.yaml creates the web service + PostgreSQL. In the Render dashboard set:
      INITIAL_ADMIN_PASSWORD   first run only - sign in as Super Admin, then remove it
      APP_BASE_URL             e.g. https://your-app.onrender.com (client invite links)
  SECRET_KEY is generated automatically. TZ=Asia/Kolkata keeps times (and AI
  reminders) on Indian time. Database tables are created/updated automatically.

AUTOMATIC EMAILS (optional)
  GMAIL_USER=<gmail address>
  GMAIL_APP_PASSWORD=<16-character Google app password>
  DEFAULT_FROM_EMAIL / DEFAULT_TO_EMAIL  (optional defaults)
  Without these, hand-off steps still open a ready email in your mail app.

AI ASSISTANT (optional key)
  Works without any key. For more natural understanding of questions set
      HELP_AI_API_KEY=<OpenAI key>
  or for DeepSeek:
      HELP_AI_API_KEY=<DeepSeek key>
      HELP_AI_BASE_URL=https://api.deepseek.com
      HELP_AI_MODEL=deepseek-chat
  The key stays on the server. The data shown always comes from the database,
  limited to what that login can see on its own dashboard.

REMINDER TONE
  Reminder pop-ups (AI reminders + overdue steps) play a loud tone for 3 seconds.
  Everyone picks their own in Settings -> Reminder tone: Bell chime (default), Ding-dong,
  Marimba, Phone ring, Alarm clock, Beep beep or Siren. The tones are built into the app.
