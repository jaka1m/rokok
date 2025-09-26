import {
    API_KEY,
    API_EMAIL,
    ACCOUNT_ID,
    ZONE_ID,
    SERVICE_NAME,
    ROOT_DOMAIN,
    BAD_WORDS_LIST
} from './config.js';

export class CloudflareApi {
    constructor(env) {
        this.env = env;
        this.headers = {
            "Authorization": `Bearer ${API_KEY(env)}`,
            "X-Auth-Email": API_EMAIL(env),
            "X-Auth-Key": API_KEY(env),
        };
    }

    async getDomainList() {
        const url = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID(this.env)}/workers/domains`;
        const res = await fetch(url, {
            headers: this.headers,
        });

        if (res.status == 200) {
            const respJson = await res.json();
            return respJson.result
                .filter((data) => data.service === SERVICE_NAME(this.env))
                .map((data) => ({ id: data.id, hostname: data.hostname }));
        }
        return [];
    }

    async registerDomain(domain) {
        domain = domain.toLowerCase();
        const registeredDomains = await this.getDomainList();

        if (!domain.endsWith(ROOT_DOMAIN(this.env))) return 400;
        if (registeredDomains.some(d => d.hostname === domain)) return 409;

        try {
            // Cek apakah subdomain mengandung kata-kata yang tidak pantas
            const badWordsListRes = await fetch(BAD_WORDS_LIST);
            if (badWordsListRes.status === 200) {
                const badWordsList = (await badWordsListRes.text()).split("\n");
                for (const badWord of badWordsList) {
                    if (domain.includes(badWord.toLowerCase())) {
                        return 403; // Forbidden
                    }
                }
            } else {
                // Gagal mengambil daftar kata-kata buruk, anggap saja aman untuk saat ini
                // atau kembalikan error jika keamanan lebih diutamakan.
                console.warn("Could not fetch bad words list.");
            }
        } catch (e) {
            console.error("Error checking bad words:", e);
            return 400; // Bad Request
        }

        const url = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID(this.env)}/workers/domains`;
        const res = await fetch(url, {
            method: "PUT",
            body: JSON.stringify({
                environment: "production",
                hostname: domain,
                service: SERVICE_NAME(this.env),
                zone_id: ZONE_ID(this.env),
            }),
            headers: {
                ...this.headers,
                'Content-Type': 'application/json'
            },
        });

        return res.status;
    }

    async deleteDomain(domainId) {
        const url = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID(this.env)}/workers/domains/${domainId}`;
        const res = await fetch(url, {
            method: "DELETE",
            headers: this.headers,
        });

        return res.status;
    }
}