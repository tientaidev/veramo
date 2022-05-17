import {
  createAgent,
  CredentialPayload,
  IDIDManager,
  IIdentifier,
  IKeyManager,
  IResolver,
  TAgent,
} from '../../../core/src'
import { CredentialIssuer, ICredentialIssuer } from '../../../credential-w3c/src'
import { DIDManager, MemoryDIDStore } from '../../../did-manager/src'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '../../../key-manager/src'
import { KeyManagementSystem } from '../../../kms-local/src'
import { getDidKeyResolver, KeyDIDProvider } from '../../../did-provider-key/src'
import { DIDResolverPlugin } from '../../../did-resolver/src'
import { EthrDIDProvider } from "../../../did-provider-ethr/src";
import { ContextDoc } from '../types'
import { CredentialIssuerLD } from '../action-handler'
import { LdDefaultContexts } from '../ld-default-contexts'
import { VeramoEd25519Signature2018 } from '../suites/Ed25519Signature2018'
import { Resolver } from 'did-resolver'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'
import { VeramoEcdsaSecp256k1RecoverySignature2020 } from "../suites/EcdsaSecp256k1RecoverySignature2020";

jest.setTimeout(300000)

const customContext: Record<string, ContextDoc> = {
  'custom:example.context': {
    '@context': {
      nothing: 'custom:example.context#blank',
    },
  },
}

const infuraProjectId = '3586660d179141e3801c3895de1c2eba'

describe('credential-LD full flow', () => {
  let didKeyIdentifier: IIdentifier
  let didEthrIdentifier: IIdentifier
  let agent: TAgent<IResolver & IKeyManager & IDIDManager & ICredentialIssuer>

  beforeAll(async () => {
    agent = createAgent({
      plugins: [
        new KeyManager({
          store: new MemoryKeyStore(),
          kms: {
            local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
          },
        }),
        new DIDManager({
          providers: {
            'did:key': new KeyDIDProvider({ defaultKms: 'local' }),
            'did:ethr:goerli': new EthrDIDProvider({
              defaultKms: 'local',
              network: 'goerli',
            }),
          },
          store: new MemoryDIDStore(),
          defaultProvider: 'did:key',
        }),
        new DIDResolverPlugin({
          resolver: new Resolver({
            ...getDidKeyResolver(),
            ...ethrDidResolver({ infuraProjectId, }),
          }),
        }),
        new CredentialIssuer(),
        new CredentialIssuerLD({
          contextMaps: [LdDefaultContexts, customContext],
          suites: [new VeramoEd25519Signature2018(), new VeramoEcdsaSecp256k1RecoverySignature2020()],
        }),
      ],
    })
    didKeyIdentifier = await agent.didManagerCreate()
    didEthrIdentifier = await agent.didManagerCreate({ provider: "did:ethr:goerli" })
  })

  it('works with Ed25519Signature2018', async () => {
    const credential: CredentialPayload = {
      issuer: didKeyIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    expect(verifiableCredential).toBeDefined()

    const verified = await agent.verifyCredential({
      credential: verifiableCredential,
    })

    expect(verified).toBe(true)
  })

  it('works with EcdsaSecp256k1RecoveryMethod2020', async () => {
    const credential: CredentialPayload = {
      issuer: didEthrIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    expect(verifiableCredential).toBeDefined()

    const verified = await agent.verifyCredential({
      credential: verifiableCredential,
    })

    expect(verified).toBe(true)
  })

  it('works with Ed25519Signature2018 presentation', async () => {
    const credential: CredentialPayload = {
      issuer: didKeyIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential1 = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    const verifiablePresentation = await agent.createVerifiablePresentation({
      presentation: {
        verifiableCredential: [verifiableCredential1],
        holder: didKeyIdentifier.did
      },
      proofFormat: 'lds',
    })

    expect(verifiablePresentation).toBeDefined()

    const verified = await agent.verifyPresentation({
      presentation: verifiablePresentation,
      challenge: "VERAMO",
    })

    expect(verified).toBe(true)
  })

  it('works with EcdsaSecp256k1RecoveryMethod2020 presentation', async () => {
    const credential: CredentialPayload = {
      issuer: didKeyIdentifier.did,
      '@context': ['custom:example.context'],
      credentialSubject: {
        nothing: 'else matters',
      },
    }
    const verifiableCredential1 = await agent.createVerifiableCredential({
      credential,
      proofFormat: 'lds',
    })

    const verifiablePresentation = await agent.createVerifiablePresentation({
      presentation: {
        verifiableCredential: [verifiableCredential1],
        holder: didEthrIdentifier.did
      },
      proofFormat: 'lds',
    })

    expect(verifiablePresentation).toBeDefined()

    const verified = await agent.verifyPresentation({
      presentation: verifiablePresentation,
      challenge: "VERAMO",
    })

    expect(verified).toBe(true)
  })
})
