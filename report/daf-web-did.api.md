## API Report File for "daf-web-did"

> Do not edit this file. It is a report generated by [API Extractor](https://api-extractor.com/).

```ts

import { AbstractIdentityProvider } from 'daf-identity-manager';
import { IAgentContext } from 'daf-core';
import { IIdentity } from 'daf-core';
import { IKey } from 'daf-core';
import { IKeyManager } from 'daf-core';
import { IService } from 'daf-core';

// @public (undocumented)
export class WebIdentityProvider extends AbstractIdentityProvider {
    constructor(options: {
        defaultKms: string;
    });
    // (undocumented)
    addKey({ identity, key, options }: {
        identity: IIdentity;
        key: IKey;
        options?: any;
    }, context: IContext): Promise<any>;
    // (undocumented)
    addService({ identity, service, options }: {
        identity: IIdentity;
        service: IService;
        options?: any;
    }, context: IContext): Promise<any>;
    // Warning: (ae-forgotten-export) The symbol "IContext" needs to be exported by the entry point index.d.ts
    //
    // (undocumented)
    createIdentity({ kms, alias }: {
        kms?: string;
        alias?: string;
    }, context: IContext): Promise<Omit<IIdentity, 'provider'>>;
    // (undocumented)
    deleteIdentity(identity: IIdentity, context: IContext): Promise<boolean>;
    // (undocumented)
    removeKey(args: {
        identity: IIdentity;
        kid: string;
        options?: any;
    }, context: IContext): Promise<any>;
    // (undocumented)
    removeService(args: {
        identity: IIdentity;
        id: string;
        options?: any;
    }, context: IContext): Promise<any>;
}


```