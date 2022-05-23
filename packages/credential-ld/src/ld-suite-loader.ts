import { VeramoLdSignature } from './ld-suites'
import { TKeyType } from '@veramo/core'

/**
 * Initializes a list of Veramo-wrapped LD Signature suites and exposes those to the Agent Module
 */
export class LdSuiteLoader {
  constructor(options: { veramoLdSignatures: VeramoLdSignature[] }) {
    options.veramoLdSignatures.forEach((obj) => {
      // FIXME: different key types could support different signature types and different Verification Methods.
      this.signatureMap[obj.getSupportedVeramoKeyTypes()[0]] = obj
      this.signatureMap[obj.getSupportedVerificationTypes()[0]] = obj
    })
  }
  private signatureMap: Record<string, VeramoLdSignature> = {}

  getSignatureSuiteForKeyType(type: TKeyType) {
    const suite = this.signatureMap[type]
    if (suite) return suite

    throw new Error('No Veramo LD Signature Suite for ' + type)
  }

  getAllSignatureSuites() {
    return Object.values(this.signatureMap)
  }

  getAllSignatureSuiteTypes(): string[] {
    return Array.from(Object.values(this.signatureMap)).map((x) => x.getSupportedVerificationTypes()).flat()
  }
}
