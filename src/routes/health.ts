/**
 * Health + operator status routes.
 */

import type { FastifyInstance } from 'fastify';
import type { SupervisorStatus } from '../services/connectivity-supervisor.js';

export interface HealthRouteDeps {
  /**
   * Live connectivity snapshot from the supervisor.
   *
   * Optional so a process without a supervisor (tests, a build with relay
   * recovery disabled) still serves `/health`; the connectivity route then answers
   * 503 and SAYS so, rather than reporting an empty object as if everything were
   * fine.
   */
  getConnectivityStatus?: () => SupervisorStatus;
}

export function registerHealthRoute(app: FastifyInstance, deps: HealthRouteDeps = {}): void {
  app.get('/health', async () => {
    return { status: 'ok', service: 'utility-server', time: new Date().toISOString() };
  });

  /**
   * Operator surface for server connectivity — the counterpart of the AGENT's
   * `/api/bootstrap/status`.
   *
   * Why it exists: this server is the component whose missing relay reservation
   * caused the outage class, and it had the LEAST visibility — diagnosing a NAT'd
   * agent that could not reach it meant reading logs. The payload answers the
   * questions an operator actually asks during that: is bootstrap registration
   * succeeding, is the relay reservation held, and WHICH member is stuck, with
   * what reason and when the next attempt is.
   */
  app.get('/health/connectivity', async (_req, reply) => {
    if (!deps.getConnectivityStatus) {
      return reply.code(503).send({
        error: {
          message:
            'connectivity supervisor is not running in this process — no connectivity status to report',
        },
      });
    }
    return {
      status: 'ok',
      service: 'utility-server',
      time: new Date().toISOString(),
      connectivity: deps.getConnectivityStatus(),
    };
  });
}
