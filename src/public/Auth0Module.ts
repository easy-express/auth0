import { EasyExpressServer, IEasyExpressAttachableModule } from '@easy-express/server';

import jwt, { RequestHandler } from 'express-jwt';
import jwtAuthz from 'express-jwt-authz';
import jwksRsa from 'jwks-rsa';

/**
 * A module that helps you add private or restricted routes to your EasyExpressServer.
 */
export class Auth0Module implements IEasyExpressAttachableModule {
  // Authorization middleware. When used, the
  // Access Token must exist and be verified against
  // the Auth0 JSON Web Key Set
  private checkJwt: jwt.RequestHandler;
  private server: EasyExpressServer | undefined;

  /**
   * Constructs an Auth0Module that initializes the jwt handler.
   *
   * @param auth0Domain the auth0 domain
   * @param auth0Audience the auth0 audience
   */
  constructor(auth0Domain?: string, auth0Audience?: string) {
    this.checkJwt = jwt({
      // Dynamically provide a signing key
      // based on the kid in the header and
      // the signing keys provided by the JWKS endpoint.
      secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${auth0Domain ? auth0Domain : process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
      }),
      // Validate the audience and the issuer.
      audience: auth0Audience ? auth0Audience : process.env.AUTH0_AUDIENCE,
      issuer: `https://${auth0Domain ? auth0Domain : process.env.AUTH0_DOMAIN}/`,
      algorithms: ['RS256'],
    });
  }

  /**
   * Saves a reference to the EasyExpressServer so routes can be attached later.
   *
   * @param server the EasyExpressServer to attach to
   */
  public attachTo(server: EasyExpressServer): Promise<unknown> {
    this.server = server;
    return new Promise(() => {
      // DO NOTHING
    });
  }

  /**
   * Defines a public GET route.
   * @param route the route
   * @param handler the handler for the route
   */
  public definePublicGet(route: string, handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.get(route, handler);
  }

  /**
   * Defines a GET route that can only be accessed by users with certain permissions (scopes).
   * @param route the route
   * @param scopes a list of the scopes the user must have
   * @param handler the handler for the route
   */
  public defineScopedGet(route: string, scopes: string[], handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.get(route, this.checkJwt, jwtAuthz(scopes), handler);
  }

  /**
   * Defines a private GET route that can only be accessed by authenticated users.
   * @param route the route
   * @param handler the handler for the route
   */
  public definePrivateGet(route: string, handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.get(route, this.checkJwt, handler);
  }

  /**
   * Defines a private POST route that can only be accessed by authenticated users.
   * @param route the route
   * @param handler the handler for the route
   */
  public definePrivatePost(route: string, handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.post(route, this.checkJwt, handler);
  }

  /**
   * Defines a public POST route.
   * @param route the route
   * @param handler the handler for the route
   */
  public definePublicPost(route: string, handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.post(route, handler);
  }

  /**
   * Defines a POST route that can only be accessed by users with certain permissions (scopes).
   * @param route the route
   * @param scopes a list of the scopes the user must have
   * @param handler the handler for the route
   */
  public defineScopedPost(route: string, scopes: string[], handler: RequestHandler[]) {
    this.verifyServerIsAttached();
    this.server?.instance.post(route, this.checkJwt, jwtAuthz(scopes), handler);
  }

  /**
   * Ensures this module is attached to a server.
   */
  private verifyServerIsAttached() {
    if (this.server === undefined) {
      throw new Error('You must first attach this Auth0Module to an EasyExpressServer.');
    }
  }
}
