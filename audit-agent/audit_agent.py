"""
AUDIT ANALYSIS AGENT - Pure ReAct, SQL-first, autonomous.
Outputs structured JSON so the UI can display reasoning steps.
"""

import shlex
import os
import sys
import json
from groq import Groq
from dotenv import load_dotenv
import psycopg2
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

load_dotenv()

# ======================================================================
# POSTGRESQL TOOLS
# ======================================================================

def query_postgres(query: str):
    sql_upper = query.strip().upper()
    if not sql_upper.startswith("SELECT"):
        return "Error: Only SELECT queries are allowed."
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "GRANT"]
    if any(keyword in sql_upper for keyword in forbidden):
        return "Error: Write operations or schema changes are not permitted."
    try:
        conn = psycopg2.connect(
            host=os.getenv("PG_HOST"),
            port=os.getenv("PG_PORT"),
            dbname=os.getenv("PG_DATABASE"),
            user=os.getenv("PG_USER"),
            password=os.getenv("PG_PASSWORD")
        )
        cur = conn.cursor()
        cur.execute(query)
        colnames = [desc[0] for desc in cur.description] if cur.description else []
        rows = cur.fetchall()
        cur.close()
        conn.close()
        if not rows:
            return "Query returned no rows."
        header = " | ".join(colnames)
        lines = [header, "-" * len(header)]
        for row in rows[:20]:
            lines.append(" | ".join(str(cell) if cell is not None else "NULL" for cell in row))
        if len(rows) > 20:
            lines.append(f"... and {len(rows) - 20} more rows.")
        return "\n".join(lines)
    except Exception as e:
        return f"Database error: {str(e)}"


def list_tables():
    try:
        conn = psycopg2.connect(
            host=os.getenv("PG_HOST"),
            port=os.getenv("PG_PORT"),
            dbname=os.getenv("PG_DATABASE"),
            user=os.getenv("PG_USER"),
            password=os.getenv("PG_PASSWORD")
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' ORDER BY table_name;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        if not rows:
            return "No tables found in public schema."
        return f"Available tables: {', '.join(row[0] for row in rows)}"
    except Exception as e:
        return f"Error listing tables: {str(e)}"


def get_table_schema(table_name: str):
    try:
        conn = psycopg2.connect(
            host=os.getenv("PG_HOST"),
            port=os.getenv("PG_PORT"),
            dbname=os.getenv("PG_DATABASE"),
            user=os.getenv("PG_USER"),
            password=os.getenv("PG_PASSWORD")
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = %s ORDER BY ordinal_position;
        """, (table_name,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        if not rows:
            return f"Table '{table_name}' not found or no access."
        lines = [f"Schema for '{table_name}':", "Column | Type | Nullable", "------|------|---------"]
        for col, dtype, nullable in rows:
            lines.append(f"{col} | {dtype} | {nullable}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error getting schema: {str(e)}"


def get_distinct_statuses():
    return query_postgres("SELECT DISTINCT status FROM audit_events WHERE status IS NOT NULL;")


def user_exists(user_id):
    result = query_postgres(f"SELECT 1 FROM audit_events WHERE user_id = '{user_id}' LIMIT 1")
    return "1" in result and "No rows" not in result and "Error" not in result


# ======================================================================
# ACTION TOOLS
# ======================================================================

def create_security_alert(user_id, severity, reason):
    try:
        if not user_exists(user_id):
            return f"Cannot create alert: User {user_id} has no audit events."
        os.makedirs("alerts", exist_ok=True)
        alert_id = f"ALERT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        timestamp = datetime.now()
        with open(f"alerts/{alert_id}.json", "w", encoding="utf-8") as f:
            json.dump({"alert_id": alert_id, "user_id": user_id, "severity": severity,
                       "reason": reason, "timestamp": timestamp.isoformat(),
                       "status": "OPEN", "created_by": "audit-agent"}, f, indent=2)
        with open(f"alerts/{alert_id}.txt", "w", encoding="utf-8") as f:
            f.write(f"SECURITY ALERT\n{'='*70}\n\nAlert ID: {alert_id}\n")
            f.write(f"User ID: {user_id}\nSeverity: {severity}\nStatus: OPEN\n")
            f.write(f"Created: {timestamp}\n\nREASON:\n{'-'*70}\n{reason}\n")
        return f"Security alert created: {alert_id} (severity: {severity})"
    except Exception as e:
        return f"Failed to create alert: {str(e)}"


def send_email_alert(recipient, user_id, subject, body_text, body_html=None):
    try:
        if not user_exists(user_id):
            return f"Cannot send email: User {user_id} has no audit events."
        smtp_server = os.getenv("SMTP_SERVER", "localhost")
        smtp_port = int(os.getenv("SMTP_PORT", "1025"))
        sender_email = os.getenv("SMTP_USER", "agent@awb.bank")
        sender_password = os.getenv("SMTP_PASSWORD", "")
        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body_text, 'plain'))
        if body_html:
            msg.attach(MIMEText(body_html, 'html'))
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                if sender_password:
                    server.login(sender_email, sender_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_server not in ("localhost", "127.0.0.1") and sender_password:
                    server.starttls()
                    server.login(sender_email, sender_password)
                server.send_message(msg)
        os.makedirs("email_logs", exist_ok=True)
        with open(f"email_logs/sent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w", encoding="utf-8") as f:
            f.write(f"To: {recipient}\nSubject: {subject}\nTime: {datetime.now()}\nBody:\n{body_text}\n")
        return f"Email sent to {recipient} - Subject: {subject}"
    except Exception as e:
        return f"Failed to send email: {str(e)}"


def generate_report(user_id, analysis):
    try:
        if not user_exists(user_id):
            return f"Cannot generate report: User {user_id} has no audit events."
        os.makedirs("reports", exist_ok=True)
        report_id = f"REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        timestamp = datetime.now()
        with open(f"reports/{report_id}.json", "w", encoding="utf-8") as f:
            json.dump({"report_id": report_id, "user_id": user_id, "analysis": analysis,
                       "timestamp": timestamp.isoformat(), "generated_by": "audit-agent"}, f, indent=2)
        with open(f"reports/{report_id}.txt", "w", encoding="utf-8") as f:
            f.write(f"SECURITY ANALYSIS REPORT\n{'='*70}\n\n")
            f.write(f"Report ID: {report_id}\nUser ID: {user_id}\nGenerated: {timestamp}\n\n")
            f.write(f"ANALYSIS:\n{'-'*70}\n{analysis}\n")
        return f"Report generated: {report_id}"
    except Exception as e:
        return f"Failed to generate report: {str(e)}"


def request_manual_review(user_id, urgency, reason):
    try:
        if not user_exists(user_id):
            return f"Cannot request review: User {user_id} has no audit events."
        os.makedirs("review_requests", exist_ok=True)
        request_id = f"REVIEW-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        with open(f"review_requests/{request_id}.json", "w", encoding="utf-8") as f:
            json.dump({"request_id": request_id, "user_id": user_id, "urgency": urgency,
                       "reason": reason, "requested_at": datetime.now().isoformat(),
                       "requested_by": "audit-agent", "status": "PENDING"}, f, indent=2)
        return f"Manual review requested: {request_id} (urgency: {urgency})"
    except Exception as e:
        return f"Failed to request review: {str(e)}"


# ======================================================================
# ARGUMENT PARSER
# ======================================================================

def parse_action(text):
    lines = text.strip().split('\n')
    for line in lines:
        if line.startswith('ACTION:'):
            action_text = line.replace('ACTION:', '', 1).strip()
            if '(' not in action_text and ')' not in action_text:
                return action_text.strip(), [], {}
            start_idx = action_text.find('(')
            tool_name = action_text[:start_idx].strip()
            depth = 1
            in_single_quote = False
            in_double_quote = False
            end_idx = start_idx + 1
            while end_idx < len(action_text) and depth > 0:
                char = action_text[end_idx]
                if char == "'" and not in_double_quote:
                    in_single_quote = not in_single_quote
                elif char == '"' and not in_single_quote:
                    in_double_quote = not in_double_quote
                if not in_single_quote and not in_double_quote:
                    if char == '(':
                        depth += 1
                    elif char == ')':
                        depth -= 1
                end_idx += 1
            if depth != 0:
                return None, None, None
            args_part = action_text[start_idx + 1:end_idx - 1].strip()
            if not args_part:
                return tool_name, [], {}
            lex = shlex.shlex(args_part, posix=True)
            lex.whitespace = ','
            lex.whitespace_split = True
            lex.commenters = ''
            tokens = list(lex)
            args = []
            kwargs = {}
            for token in tokens:
                token = token.strip()
                if '=' in token:
                    key, val = token.split('=', 1)
                    key = key.strip()
                    val = val.strip()
                    if val.isdigit():
                        val = int(val)
                    elif val.replace('.', '', 1).isdigit():
                        val = float(val)
                    elif val.lower() == 'true':
                        val = True
                    elif val.lower() == 'false':
                        val = False
                    elif val.lower() == 'none':
                        val = None
                    else:
                        if (val.startswith('"') and val.endswith('"')) or \
                                (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                    kwargs[key] = val
                else:
                    val = token
                    if val.isdigit():
                        val = int(val)
                    elif val.replace('.', '', 1).isdigit():
                        val = float(val)
                    elif val.lower() == 'true':
                        val = True
                    elif val.lower() == 'false':
                        val = False
                    elif val.lower() == 'none':
                        val = None
                    else:
                        if (val.startswith('"') and val.endswith('"')) or \
                                (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                    args.append(val)
            return tool_name, args, kwargs
    return None, None, None


# ======================================================================
# AGENT CLASS
# ======================================================================

class AuditAgent:
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.tools = {
            "query_postgres": query_postgres,
            "list_tables": list_tables,
            "get_table_schema": get_table_schema,
            "get_distinct_statuses": get_distinct_statuses,
            "create_security_alert": create_security_alert,
            "send_email_alert": send_email_alert,
            "generate_report": generate_report,
            "request_manual_review": request_manual_review,
        }
        self.system_prompt = """You are an autonomous security analyst agent for AWB Bank's audit system.
You have direct SQL read-only access to the audit database and must analyze the ENTIRE system, not just individual users.

AVAILABLE TOOLS:

SQL RETRIEVAL:
- list_tables() - List all tables. Call this first if unsure what exists.
- get_table_schema(table_name) - Get columns before writing any SQL.
- query_postgres(query) - Execute a SELECT query. Always include LIMIT.
- get_distinct_statuses() - Get valid status values from audit_events.

ACTIONS (only use when genuinely warranted by data):
- create_security_alert(user_id, severity, reason) - severity: LOW/MEDIUM/HIGH/CRITICAL
- send_email_alert(recipient, user_id, subject, body_text) - recipient always "aandadiasmaa@gmail.com"
- generate_report(user_id, analysis)
- request_manual_review(user_id, urgency, reason)

STRICT RULES:
1. NEVER invent data. If a tool returns no rows, that IS the answer.
2. NEVER output FINAL ANSWER in the same response as ACTION lines.
3. ALWAYS verify user exists before any action: query_postgres("SELECT 1 FROM audit_events WHERE user_id='X' LIMIT 1")
4. NEVER repeat an action for the same user in one session.
5. Valid statuses are: FAILURE, PENDING, SUCCESS. Never guess.
6. NEVER guess column names. Always call get_table_schema() first.

GLOBAL ANALYSIS APPROACH:
When asked global questions like "are there suspicious users" or "show security overview":
- Query ALL users, not just one. Use GROUP BY user_id.
- Compute failure rates: COUNT(CASE WHEN status='FAILURE' THEN 1 END) / COUNT(*) per user.
- Check for off-hours activity: EXTRACT(HOUR FROM timestamp) NOT BETWEEN 6 AND 22.
- Find high event volume: users with event counts far above the average.
- Check CRITICAL severity events across all users.
- Look for sensitive event types: LOGIN_FAILED, DELETE, ADMIN, UPDATE patterns.
- Compare each user to the global average using subqueries.

REACT WORKFLOW - TWO TURNS, NEVER COMBINED:
Turn 1: Write your Thought, then ACTION lines only. No FINAL ANSWER yet.
Turn 2: Write your Thought, then FINAL ANSWER only. No ACTION lines.

THOUGHT FORMAT:
Always start with "Thought:" explaining what you are doing and why.
Example:
Thought: The user wants a global security overview. I will first check the schema, then query failure rates per user, then check for off-hours activity across all users.
ACTION: get_table_schema(audit_events)
ACTION: query_postgres(query="SELECT user_id, COUNT(*) as total, COUNT(CASE WHEN status='FAILURE' THEN 1 END) as failures FROM audit_events GROUP BY user_id ORDER BY failures DESC LIMIT 20")

Now begin. Always think globally first unless a specific user is mentioned."""

    def call_llm(self, messages):
        response = self.client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            temperature=0
        )
        return response.choices[0].message.content

    def execute_tool(self, tool_name, args, kwargs):
        if tool_name not in self.tools:
            return f"Error: unknown tool '{tool_name}'"
        try:
            return self.tools[tool_name](*args, **kwargs)
        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"

    def run(self, question, max_steps=20, structured=False):
        """
        Run the agent.
        structured=True  -> prints STEP_JSON: lines for the UI to parse
        structured=False -> normal terminal output
        """
        MAX_ACTIONS_PER_STEP = 5
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": question}
        ]
        steps = []

        for step_num in range(1, max_steps + 1):
            llm_reply = self.call_llm(messages)

            # Extract thought
            thought = ""
            for line in llm_reply.split('\n'):
                if line.strip().lower().startswith("thought:"):
                    thought = line.strip()[len("thought:"):].strip()
                    break

            # ── Final answer ──
            if "FINAL ANSWER:" in llm_reply and "ACTION:" not in llm_reply:
                final_part = llm_reply.split("FINAL ANSWER:")[-1].strip()
                final_part = final_part.replace("You: quit", "").replace("Goodbye!", "").strip()

                if structured:
                    step_data = {"type": "final", "thought": thought, "answer": final_part, "steps": steps}
                    print(f"STEP_JSON:{json.dumps(step_data, ensure_ascii=False)}")
                else:
                    print(f"\nFINAL ANALYSIS:\n{final_part}\n")
                    print("=" * 70)
                return final_part

            # ── Parse and execute actions ──
            action_lines = [l for l in llm_reply.split('\n') if l.strip().startswith('ACTION:')]
            observations = []
            tool_calls = []
            action_count = 0

            for line in action_lines:
                if action_count >= MAX_ACTIONS_PER_STEP:
                    break
                action_count += 1
                tool_name, args, kwargs = parse_action(line)
                if tool_name:
                    observation = self.execute_tool(tool_name, args, kwargs)
                    observations.append(f"Tool: {tool_name}\nResult: {observation}")
                    tool_calls.append({"tool": tool_name, "result": observation})

            if structured and tool_calls:
                step_data = {"type": "step", "step": step_num, "thought": thought, "tools": tool_calls}
                print(f"STEP_JSON:{json.dumps(step_data, ensure_ascii=False)}", flush=True)

            steps.append({"thought": thought, "tools": tool_calls})
            messages.append({"role": "assistant", "content": llm_reply})

            if tool_calls:
                combined_obs = "\n\n".join(observations)
                messages.append({
                    "role": "user",
                    "content": (
                        f"OBSERVATIONS:\n{combined_obs}\n\n"
                        "Based on these observations, what is your next step? "
                        "If done, provide FINAL ANSWER. Do NOT include ACTION lines if concluding."
                    )
                })
            else:
                messages.append({
                    "role": "user",
                    "content": "Please use ACTION: tool_name(arguments) or provide your FINAL ANSWER:"
                })

        if structured:
            print(f"STEP_JSON:{json.dumps({'type': 'final', 'answer': 'Max steps reached.', 'steps': steps}, ensure_ascii=False)}")
        return None


# ======================================================================
# MAIN
# ======================================================================

if __name__ == "__main__":
    # ── Called by Java (stdin is not a terminal) ──────────────────────
    if not sys.stdin.isatty():
        question = ""
        for line in sys.stdin:
            line = line.strip()
            if line and line.lower() not in ("quit", "exit", "q"):
                question = line
                break
        if question:
            agent = AuditAgent()
            agent.run(question, structured=True)  # structured mode for UI
        sys.exit(0)

    # ── Interactive terminal mode ──────────────────────────────────────
    print("AWB BANK AUDIT AGENT (AUTONOMOUS, SQL-FIRST)")
    print("=" * 70)
    agent = AuditAgent()
    print("\nINTERACTIVE MODE - Ask anything about the audit logs.")
    print('Type "quit" to exit.\n')

    while True:
        try:
            user_input = input("You: ")
        except EOFError:
            break
        if user_input.lower() in ["quit", "exit", "q"]:
            print("\nGoodbye!")
            break
        if not user_input.strip():
            continue
        try:
            agent.run(user_input, structured=False)
        except KeyboardInterrupt:
            print("\n\nInterrupted.")
            break
        except Exception as e:
            print(f"\nError: {e}\n")