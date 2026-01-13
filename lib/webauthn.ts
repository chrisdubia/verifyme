import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/types";

const rpID = process.env.RP_ID || "localhost";
const rpName = "Verify Me - Trust Layer MVP";
const origin = process.env.RP_ORIGIN || "http://localhost:3000";

type ChallengeStore = Map<string, string>;
const globalAny = globalThis as any;

const registerChallenges: ChallengeStore =
  globalAny.__regChallenges ?? (globalAny.__regChallenges = new Map());
const authChallenges: ChallengeStore =
  globalAny.__authChallenges ?? (globalAny.__authChallenges = new Map());

export function getRp() {
  return { rpID, rpName, origin };
}

export async function createRegistrationOptions(args: {
  userId: string;
  userName: string;
  existingCredentialIDs: Buffer[];
}) {
  const { rpID, rpName } = getRp();
  const opts = await generateRegistrationOptions({
    rpID,
    rpName,
    userID: Buffer.from(args.userId),
    userName: args.userName,
    attestationType: "none",
    excludeCredentials: args.existingCredentialIDs.map((id) => ({
    id: id.toString("base64url"),
  })),

    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  registerChallenges.set(args.userId, opts.challenge);
  return opts;
}

export async function verifyRegistration(args: {
  userId: string;
  response: RegistrationResponseJSON;
}) {
  const { rpID, origin } = getRp();
  const expectedChallenge = registerChallenges.get(args.userId);
  if (!expectedChallenge) throw new Error("Missing registration challenge");

  const verification: VerifiedRegistrationResponse =
    await verifyRegistrationResponse({
      response: args.response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

  if (!verification.verified) throw new Error("Registration not verified");
  registerChallenges.delete(args.userId);

  return verification;
}

export async function createAuthOptions(args: {
  userId: string;
  allowCredentialIDs: Buffer[];
}) {
  const { rpID } = getRp();
  const opts = await generateAuthenticationOptions({
    rpID,
    allowCredentials: args.allowCredentialIDs.map((id) => ({
  id: id.toString("base64url"),
  })),

    userVerification: "preferred",
  });

  authChallenges.set(args.userId, opts.challenge);
  return opts;
}

export async function verifyAuth(args: {
  userId: string;
  response: AuthenticationResponseJSON;
  credential: {
    credentialID: Buffer;
    credentialPublicKey: Buffer;
    counter: number;
  };
}) {
  const { rpID, origin } = getRp();
  const expectedChallenge = authChallenges.get(args.userId);
  if (!expectedChallenge) throw new Error("Missing auth challenge");

  const verification: VerifiedAuthenticationResponse =
    await verifyAuthenticationResponse({
      response: args.response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: args.credential.credentialID.toString("base64url"),
        credentialPublicKey: args.credential.credentialPublicKey,
        counter: args.credential.counter,
},
      },
    });

  if (!verification.verified) throw new Error("Auth not verified");
  authChallenges.delete(args.userId);

  return verification;
}
