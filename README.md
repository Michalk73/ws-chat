Chat z E2E.

Chat oparty na websocket dla rozmowy w czasie rzeczywistym. 
Szyfrowanie po stronie klienta w przegladarce, tylko 1 skrypt AES do szyfrowania.
1. CSS wbudowane w html.
2. Brak zapisywania historii wiadomosci na dysku. Zaszyfrowane wiadomości są w pamięci RAM aż do ostatniego online użytkownika chat.
3.Serwer nie zna hasła szyfrowania po stronie przegladarki.
4.Po dołączeniu nowego użytkownika do pokoju zostanie wysłana do niego ostatnie wiadomości z historii z pamięci RAM zaszyfrowane. Dopiero po stronie klienta przegladarka odszyfruje je.
5. Po wyjściu ostaniego użytkownika z pokoju, sesja pokoju ws zostaje unicestwiona wraz z historią.
6.Użytkonicy dołączajacy się do danego chat muszą znać wspólne haslo.
7. Można wysyłać między sobą wiadomości prywatne pomiedzy użytkownikami danego pokoju.

Frontend : 
-index.html
-crypto-js.min.js

Backend:
-app.py  - fastapi serwer z websoket
-settings.json - ustawienia wstępne

______________________________

E2E Chat.

A WebSocket-based chat for real-time conversation.
Client-side encryption within the browser; uses a single AES script for encryption.
1. CSS embedded in the HTML.
2. No message history saved to disk; encrypted messages remain in RAM until the last user leaves the chat.
3. The server does not know the client-side encryption password.
4. When a new user joins a room, the encrypted message history from RAM is sent to them; the browser decrypts the messages only on the client side.
5. When the last user leaves the room, the WebSocket room session and its history are destroyed.
6. Users joining a specific chat must know the shared password.
7. Users within the same room can send private messages to one another.

Frontend:
- index.html
- crypto-js.min.js
Backend:
- app.py – FastAPI server with WebSockets
- settings.json – initial settings
