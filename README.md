# note-management-system-161753-161763

Notes Backend (ASP.NET Core 8, EF Core, JWT, NSwag)

Quick start:
1. Navigate to notes_backend
2. Configure env vars (optional in dev). For production set JWT__KEY.
3. Run: `dotnet run`
4. Open API docs: http://localhost:3001/docs

Default dev user is seeded:
- Email: demo@notes.app
- Password: demo1234

Auth:
- POST /auth/register
- POST /auth/login

Notes (require Authorization: Bearer <token>):
- GET /notes
- GET /notes/{id}
- POST /notes
- PUT /notes/{id}
- DELETE /notes/{id}

Environment variables:
- DB_CONNECTION_STRING
- JWT__KEY
- JWT__ISSUER
- JWT__AUDIENCE
