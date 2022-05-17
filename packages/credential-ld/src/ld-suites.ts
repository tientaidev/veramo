import {
  CredentialPayload,
  IAgentContext,
  IKey,
  IKeyManager,
  IResolver,
  PresentationPayload,
  TKeyType,
} from '@veramo/core'
import { DIDDocument } from 'did-resolver/src/resolver'

export type RequiredAgentMethods = IResolver & Pick<IKeyManager, 'keyManagerGet' | 'keyManagerSign'>

export abstract class VeramoLdSignature {
  // LinkedDataSignature Suites according to
  // https://github.com/digitalbazaar/jsonld-signatures/blob/main/lib/suites/LinkedDataSignature.js
  // Add type definition as soon as https://github.com/digitalbazaar/jsonld-signatures
  // supports those.

  abstract getSupportedVerificationTypes(): string[]

  abstract getSupportedVeramoKeyTypes(): string[]

  abstract getSigningSuiteInstance(
    key: IKey,
    issuerDid: string,
    verificationMethodId: string,
    agentContext: IAgentContext<RequiredAgentMethods>,
  ): any

  abstract getVerificationSuiteInstance(): any

  abstract preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void

  abstract preSigningCredModification(credential: CredentialPayload): void

  preSigningPresModification(presentation: PresentationPayload): void {
    // TODO: Remove invalid field 'verifiers' from Presentation. Needs to be adapted for LD credentials
    // Only remove empty array (vc.signPresentation will throw then)
    const sanitizedPresentation = presentation as any
    if (sanitizedPresentation?.verifier?.length == 0) {
      delete sanitizedPresentation.verifier
    }
  }
}
