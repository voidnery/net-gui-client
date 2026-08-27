export namespace main {
	
	export class AppInfo {
	    version: string;
	    linked: boolean;
	    serverVersion: string;
	    apiVersion: number;
	    compatible: boolean;
	    problem: string;
	
	    static createFrom(source: any = {}) {
	        return new AppInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.version = source["version"];
	        this.linked = source["linked"];
	        this.serverVersion = source["serverVersion"];
	        this.apiVersion = source["apiVersion"];
	        this.compatible = source["compatible"];
	        this.problem = source["problem"];
	    }
	}
	export class ProfileResult {
	    ok: boolean;
	    profile: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ProfileResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ok = source["ok"];
	        this.profile = source["profile"];
	        this.error = source["error"];
	    }
	}
	export class ProfileView {
	    id: string;
	    name: string;
	    kind: string;
	    server: string;
	    port: number;
	    hasSecrets: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProfileView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.kind = source["kind"];
	        this.server = source["server"];
	        this.port = source["port"];
	        this.hasSecrets = source["hasSecrets"];
	    }
	}
	export class StatusView {
	    state: string;
	    mode: string;
	    profileId: string;
	    profileName: string;
	    listen: string;
	    policy: string;
	    ruleCount: number;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new StatusView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.mode = source["mode"];
	        this.profileId = source["profileId"];
	        this.profileName = source["profileName"];
	        this.listen = source["listen"];
	        this.policy = source["policy"];
	        this.ruleCount = source["ruleCount"];
	        this.error = source["error"];
	    }
	}

}

