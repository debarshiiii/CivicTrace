# CivicTrace

A civic issue reporting and tracking application.

## Structure
- ackend/ — FastAPI backend
- rontend/ — HTML frontend pages

## Run locally
1. Create ackend/.env locally from your own values.
2. Install backend dependencies:

   `ash
   cd backend
   pip install -r requirements.txt
   `

3. Start the backend using your local command.

## Security
- Never commit .env, API keys, passwords, database URLs, private IP addresses, or personal data.
- Use .env.example with placeholder values if you need to document required variables.
