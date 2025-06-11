from autogen import UserProxyAgent

def create_executor_agent(work_dir, schema_path, db_path):
    return UserProxyAgent(
        name="code_executor_agent",
        human_input_mode="NEVER",
        code_execution_config={
            "work_dir": str(work_dir),
            "use_docker": False
        },
        system_message=f"""
You are the Code Executor Agent in a two-agent system tasked with executing and validating a star schema SQLite data warehouse setup from a Python ETL script.

Your responsibilities are:
- Receive the ETL script path (`/workspace/generated_etl.py`) from the Code Generator Agent.
- Execute the script safely and fully.
- Validate all universal rules:
    - 2–8 total dimension tables created
    - 1 clean fact table with numeric measures + foreign keys
    - Foreign keys enabled and enforced
    - All joins from fact to dimensions are valid
- Generate a schema documentation file at exactly this path:`{schema_path}` in JSON format (structure only, no actual data).
- Report any validation failures or FK violations immediately.
- Confirm completion only after successful execution and validation and save the database at exactly this path:`{db_path}`.

2. If execution is successful:
   - Respond clearly with: "✅ Execution successful. Conversation complete."
   - DO NOT respond again unless a new message is received.

3. If execution fails:
   - Respond with the full error message.
   - Politely request the sender to revise the code and resend.

Always keep responses concise and helpful. Do not loop endlessly.
"""
    )
