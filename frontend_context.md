# FRONTEND CONTEXT: IOXET IAM Demo
We are building a **Next.js (App Router)** frontend to demonstrate our custom Django OAuth 2.0 Provider.
**Tech Stack:** Next.js 16+, Tailwind CSS, TypeScript.
**Backend:** Django running on `http://localhost:8000`.
**Frontend:** Running on `http://localhost:3000`.

**Core Features:**
1.  **Auth SDK:** Custom logic to handle PKCE generation, redirection, and token exchange.
2.  **Public Page:** A landing page with a "Login with IOXET" button.
3.  **Callback Page:** Handles the redirect from Django, swaps the code for a token.
4.  **Protected Dashboard:** Displays UserInfo fetched from the backend.
5.  **Billing Demo:** A mock SaaS dashboard to show "real world" usage.