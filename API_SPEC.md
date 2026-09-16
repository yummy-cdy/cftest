# Notes API

## Auth

Authentication uses the session cookie set by `POST /login` (form fields: `username`, `password`).

All `/api/*` endpoints require that cookie. Without a valid session the response is
`401` with a JSON body — not HTML, not a redirect.

## Note object

```json
{
  "id": 1,
  "title": "meeting",
  "body": "3pm, room 2",
  "created_at": "2026-09-16 14:02:00",
  "updated_at": "2026-09-16 14:02:00"
}
```

`id` is an integer. The other four are strings. Extra fields are allowed.

## Endpoints

### `GET /api/notes`

Returns the authenticated user's notes.

```json
{ "notes": [ <note>, ... ] }
```

`200`. Empty list if the user has no notes.

### `POST /api/notes`

`Content-Type: application/json`

```json
{ "title": "meeting", "body": "3pm, room 2" }
```

`title` is required and must not be empty. `body` is optional, defaults to `""`.

`201` with the created note object.

### `GET /api/notes/<id>`

`200` with the note object.

## Status codes

| Code | When |
|---|---|
| `200` | Success |
| `201` | Note created |
| `400` | `title` missing or empty |
| `401` | No valid session |
| `404` | Note does not exist, or belongs to another user |

Error bodies are JSON. Message text is not specified.

## Ownership

A user may only read their own notes. Requesting another user's note returns `404`, not `403`.

## Examples

```bash
curl -s -c cookie.txt -o /dev/null \
  -X POST -d "username=test&password=1234" \
  http://localhost:8000/login

curl -s -b cookie.txt http://localhost:8000/api/notes

curl -s -b cookie.txt \
  -X POST -H "Content-Type: application/json" \
  -d '{"title":"meeting","body":"3pm"}' \
  http://localhost:8000/api/notes

curl -s -b cookie.txt http://localhost:8000/api/notes/2
```
