// errors.js — erreur HTTP "attendue" : son message peut être montré au client.
// Toute autre exception est journalisée côté serveur et renvoyée comme "erreur interne" (voir index.js).
export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
