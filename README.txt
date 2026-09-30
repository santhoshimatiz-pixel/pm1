iMatiz PM Tool
==============

FILES
  server.py          the app server (Python, PostgreSQL)
  index.html         the whole web page (all dashboards)
  ai_assistant.py    floating AI chat: answers from each login's own dashboard data + reminders
  help_assistant.py  Help guide answers + the fixed "only about this PM tool" replies
  requirements.txt, Procfile, render.yaml   deployment (Render)

RUN LOCALLY
  pip install -r requirements.txt
  create a .env file next to server.py with at least:
      DATABASE_URL=postgresql://user:password@localhost:5432/matiz
      INITIAL_ADMIN_PASSWORD=<8+ characters, first run only>
  python server.py          then open http://localhost:8000

DEPLOY (Render)
  render.yaml creates the web service + PostgreSQL. In the Render dashboard set:
      INITIAL_ADMIN_PASSWORD   first run only - sign in as Super Admin, then remove it
      APP_BASE_URL             e.g. https://your-app.onrender.com (client invite links)
  SECRET_KEY is generated automatically. TZ=Asia/Kolkata keeps times (and AI
  reminders) on Indian time. Database tables are created/updated automatically.

GMAIL API  (needed on Render's FREE plan)
  Render's free web services block Gmail SMTP (ports 465/587), so emails silently
  time out there. The Gmail API sends from the SAME Gmail account over HTTPS,
  which is allowed. One-time setup (about 10 minutes):
   1. https://console.cloud.google.com -> create a project (e.g. "iMatiz Mail").
   2. APIs & Services -> Library -> search "Gmail API" -> Enable.
   3. APIs & Services -> OAuth consent screen (Google Auth Platform):
        User type External; app name "iMatiz"; your email as support/contact.
        Audience -> add santhoshimatiz@gmail.com as a test user, then click
        "Publish app" (In production). Otherwise the token dies every 7 days.
   4. Credentials (Clients) -> Create client -> OAuth client ID ->
        Application type "Desktop app" -> Create. Copy Client ID + Client secret.
   5. On your own computer:  python get_gmail_token.py
        paste the ID + secret, sign in as santhoshimatiz@gmail.com, allow
        "Send email on your behalf". (Unverified-app warning: Advanced -> Go to.)
   6. Render -> your web service -> Environment -> add the 3 printed values:
        GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN
      Keep GMAIL_USER=santhoshimatiz@gmail.com. Save -> it redeploys.
   7. Sign in as Super Admin -> Settings -> "Email sending check" -> Send test.
  When these 3 are set the app uses the Gmail API; otherwise it uses SMTP below.
  Optional: MAIL_FROM_NAME (default "iMatiz Technology") = the sender's display name.

  TROUBLESHOOTING: Settings -> Email sending check lists the last 40 emails with
  the exact reason any failed (also printed in Render -> Logs as "[email] ...").
  Forgot-password requests appear there too, e.g. "No valid email saved in this
  person's profile".

AUTOMATIC EMAILS (optional)
  GMAIL_USER=<gmail address>
  GMAIL_APP_PASSWORD=<16-character Google app password>   (SMTP: local / paid Render only)
  DEFAULT_FROM_EMAIL / DEFAULT_TO_EMAIL  (optional defaults)
  Without these, hand-off steps still open a ready email in your mail app.

  WHO RECEIVES THEM
  From is always the company Gmail account. To is the person who gets the work:
    - Team members (programmers, writers, BDCs, journal team): the Mail ID in their
      Team profile (entered when they are added, editable later).
    - Department logins (Marketing TL/Manager, Accounts, Technical Manager/TL,
      Journal Manager/TL, BDC): Settings -> My email, or an admin sets them all in
      Settings -> Department login emails.
  Examples: Technical Manager assigns a task to Janani -> Janani's email.
  BDC sends a lead -> Marketing TL (Marketing Manager copied). Each next step goes
  to whoever must act next (same rules as the reminder pop-ups).
  If someone has no email saved, the mail goes to the Default To address with a
  note saying who it was meant for.

  FORGOT PASSWORD (team members)
  On the login page, Employee ID -> "Forgot password?". A one-time reset code is
  emailed to the Mail ID in that person's Team profile (with a one-click link
  when APP_BASE_URL is set). The code expires in 30 minutes, works once, and
  locks after 5 wrong tries. Resetting signs that person out everywhere.
  Needs GMAIL_USER / GMAIL_APP_PASSWORD; without them, or with no Mail ID saved,
  a manager or Super Admin resets the password from Team & Access as before.

AI ASSISTANT (optional key)
  Works without any key. For more natural understanding of questions set
      HELP_AI_API_KEY=<OpenAI key>
  or for DeepSeek:
      HELP_AI_API_KEY=<DeepSeek key>
      HELP_AI_BASE_URL=https://api.deepseek.com
      HELP_AI_MODEL=deepseek-chat
  The key stays on the server. The data shown always comes from the database,
  limited to what that login can see on its own dashboard.

MY PROFILE (every dashboard)
  Everyone has "My profile" in the sidebar and can update it any time.
    - Team members: name, Employee ID, role, team, designation, department, branch
      and joining date are set by their manager (read-only). They fill in email,
      phone, date of birth, gender, blood group, address, emergency contact,
      about/skills and a photo. Managers see this on the person's Team card.
    - Department logins: the person using the login fills in their name,
      designation, contact and personal details. Email = where hand-offs go.
    - Clients: update email, alternate mobile, address, designation, institution,
      institutional email and department (registered phone stays read-only - it's
      their sign-in). Each change is logged in that client's history.
  A dot on "My profile" and a one-time reminder appear until email/phone are filled.

REMINDER TONE
  Reminder pop-ups (AI reminders + overdue steps) play a loud tone for 3 seconds.
  Everyone picks their own in Settings -> Reminder tone: Bell chime (default), Ding-dong,
  Marimba, Phone ring, Alarm clock, Beep beep or Siren. The tones are built into the app.
