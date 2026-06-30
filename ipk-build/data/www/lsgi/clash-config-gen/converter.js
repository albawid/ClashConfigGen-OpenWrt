/**
 * Clash Config Converter - Pure JS, zero dependencies
 * Supports: vmess://, vless://, ss://, trojan://
 */

const Converter = {
  // --- VMess ---
  decodeVmess(uri) {
    let b64 = uri.replace('vmess://', '').trim();
    const pad = 4 - (b64.length % 4);
    if (pad !== 4) b64 += '='.repeat(pad);
    const decoded = atob(b64);
    return JSON.parse(decoded);
  },

  vmessToClash(v) {
    const proxy = {
      name: v.ps || 'VMess',
      type: 'vmess',
      server: v.add,
      port: parseInt(v.port),
      uuid: v.id,
      alterId: parseInt(v.aid || 0),
      cipher: v.scy || 'auto',
      udp: true,
    };

    if (v.tls && v.tls !== 'none') {
      proxy.tls = true;
      if (v.sni) proxy.servername = v.sni;
    } else {
      proxy.tls = false;
    }
    proxy['skip-cert-verify'] = true;

    const net = v.net || 'tcp';
    if (net === 'ws') {
      proxy.network = 'ws';
      const wsOpts = { path: v.path || '/' };
      if (v.host) {
        wsOpts.headers = { Host: v.host };
      }
      proxy['ws-opts'] = wsOpts;
    } else if (net === 'grpc') {
      proxy.network = 'grpc';
      proxy['grpc-opts'] = { 'grpc-service-name': (v.path || '/').replace(/^\//, '') };
    } else if (net === 'h2') {
      proxy.network = 'h2';
      proxy['h2-opts'] = { path: v.path || '/', host: [v.host || v.add] };
    }

    return proxy;
  },

  // --- VLESS ---
  decodeVless(uri) {
    let body = uri.replace('vless://', '');
    let fragment = '';
    if (body.includes('#')) {
      [body, fragment] = body.split('#');
      fragment = decodeURIComponent(fragment);
    }
    let query = '';
    if (body.includes('?')) {
      [body, query] = body.split('?');
    }
    const [uuid, hostport] = body.split('@');
    let host, port;
    // Handle IPv6 [::1]:port
    if (hostport.startsWith('[')) {
      const bracketEnd = hostport.indexOf(']');
      host = hostport.substring(1, bracketEnd);
      port = hostport.substring(bracketEnd + 2); // skip ']:'
    } else if (hostport.includes(':')) {
      const lastColon = hostport.lastIndexOf(':');
      host = hostport.substring(0, lastColon);
      port = hostport.substring(lastColon + 1);
    } else {
      host = hostport;
      port = '443';
    }
    const params = new URLSearchParams(query);

    return {
      uuid, host, port: parseInt(port),
      ps: fragment || `VLESS-${host}`,
      net: params.get('type') || 'tcp',
      path: params.get('path') || '/',
      hostHeader: params.get('host') || host,
      security: params.get('security') || 'none',
      flow: params.get('flow') || '',
      fp: params.get('fp') || '',
      pbk: params.get('pbk') || '',
      sid: params.get('sid') || '',
      sni: params.get('sni') || '',
    };
  },

  vlessToClash(v) {
    const proxy = {
      name: v.ps,
      type: 'vless',
      server: v.host,
      port: v.port,
      uuid: v.uuid,
      udp: true,
    };

    if (v.security && v.security !== 'none') {
      proxy.tls = true;
      if (v.sni) proxy.servername = v.sni;
      else if (v.hostHeader) proxy.servername = v.hostHeader;
    } else {
      proxy.tls = false;
    }
    proxy['skip-cert-verify'] = true;

    const net = v.net;
    if (net === 'ws') {
      proxy.network = 'ws';
      const wsOpts = { path: v.path };
      if (v.hostHeader) wsOpts.headers = { Host: v.hostHeader };
      proxy['ws-opts'] = wsOpts;
    } else if (net === 'grpc') {
      proxy.network = 'grpc';
      proxy['grpc-opts'] = { 'grpc-service-name': v.path.replace(/^\//, '') };
    }

    if (v.flow) proxy.flow = v.flow;
    if (v.fp) proxy['client-fingerprint'] = v.fp;
    if (v.pbk) {
      proxy['reality-opts'] = { 'public-key': v.pbk, 'short-id': v.sid || '' };
    }

    return proxy;
  },

  // --- Shadowsocks ---
  decodeSS(uri) {
    let body = uri.replace('ss://', '');
    let fragment = '';
    if (body.includes('#')) {
      [body, fragment] = body.split('#');
      fragment = decodeURIComponent(fragment);
    }

    if (body.includes('@')) {
      const [userinfo, hostport] = body.split('@');
      // FIX: was missing = operator
      let padded = userinfo;
      const pad = 4 - (padded.length % 4);
      if (pad !== 4) padded += '='.repeat(pad);
      const decoded = atob(padded);
      const [method, password] = decoded.split(':');
      // Handle IPv6
      let host, port;
      if (hostport.startsWith('[')) {
        const bracketEnd = hostport.indexOf(']');
        host = hostport.substring(1, bracketEnd);
        port = hostport.substring(bracketEnd + 2);
      } else {
        const lastColon = hostport.lastIndexOf(':');
        host = hostport.substring(0, lastColon);
        port = hostport.substring(lastColon + 1);
      }
      return { method, password, host, port: parseInt(port), ps: fragment || `SS-${host}` };
    }
    // Fully encoded (SIP002 format without @)
    let pad = 4 - (body.length % 4);
    if (pad !== 4) body += '='.repeat(pad);
    const decoded = atob(body);
    return Converter.decodeSS('ss://' + decoded);
  },

  ssToClash(v) {
    const proxy = {
      name: v.ps,
      type: 'ss',
      server: v.host,
      port: v.port,
      cipher: v.method,
      password: v.password,
      udp: true,
      tls: false,
      'skip-cert-verify': true,
    };
    return proxy;
  },

  // --- Trojan ---
  decodeTrojan(uri) {
    let body = uri.replace('trojan://', '');
    let fragment = '';
    if (body.includes('#')) {
      [body, fragment] = body.split('#');
      fragment = decodeURIComponent(fragment);
    }
    let query = '';
    if (body.includes('?')) {
      [body, query] = body.split('?');
    }
    const [password, hostport] = body.split('@');
    let host, port;
    // Handle IPv6
    if (hostport.startsWith('[')) {
      const bracketEnd = hostport.indexOf(']');
      host = hostport.substring(1, bracketEnd);
      port = hostport.substring(bracketEnd + 2);
    } else if (hostport.includes(':')) {
      const lastColon = hostport.lastIndexOf(':');
      host = hostport.substring(0, lastColon);
      port = hostport.substring(lastColon + 1);
    } else {
      host = hostport;
      port = '443';
    }
    const params = new URLSearchParams(query);

    return {
      password, host, port: parseInt(port),
      ps: fragment || `Trojan-${host}`,
      net: params.get('type') || 'tcp',
      path: params.get('path') || '/',
      hostHeader: params.get('host') || host,
      sni: params.get('sni') || host,
      security: params.get('security') || '',
      fp: params.get('fp') || '',
      alpn: params.get('alpn') || '',
    };
  },

  trojanToClash(v) {
    const proxy = {
      name: v.ps,
      type: 'trojan',
      server: v.host,
      port: v.port,
      password: v.password,
      udp: true,
      'skip-cert-verify': true,
    };

    if (v.security && v.security !== 'none') {
      proxy.tls = true;
      if (v.sni) proxy.sni = v.sni;
      else if (v.hostHeader) proxy.sni = v.hostHeader;
      if (v.fp) proxy['client-fingerprint'] = v.fp;
      if (v.alpn) {
        proxy.alpn = v.alpn.includes(',') ? v.alpn.split(',') : [v.alpn];
      }
    } else {
      proxy.tls = false;
    }

    const net = v.net;
    if (net === 'ws') {
      proxy.network = 'ws';
      const wsOpts = { path: v.path };
      if (v.hostHeader) wsOpts.headers = { Host: v.hostHeader };
      proxy['ws-opts'] = wsOpts;
    } else if (net === 'grpc') {
      proxy.network = 'grpc';
      proxy['grpc-opts'] = { 'grpc-service-name': v.path.replace(/^\//, '') };
    }

    return proxy;
  },

  // --- Auto detect & parse ---
  parseUri(uri) {
    uri = uri.trim();
    if (uri.startsWith('vmess://')) return { proto: 'vmess', data: this.decodeVmess(uri) };
    if (uri.startsWith('vless://')) return { proto: 'vless', data: this.decodeVless(uri) };
    if (uri.startsWith('ss://')) return { proto: 'ss', data: this.decodeSS(uri) };
    if (uri.startsWith('trojan://')) return { proto: 'trojan', data: this.decodeTrojan(uri) };
    return null;
  },

  toClashProxy(proto, data) {
    const map = {
      vmess: (d) => this.vmessToClash(d),
      vless: (d) => this.vlessToClash(d),
      ss: (d) => this.ssToClash(d),
      trojan: (d) => this.trojanToClash(d),
    };
    return map[proto](data);
  },

  // --- YAML generator ---
  toYaml(obj, indent = 0) {
    const spaces = '  '.repeat(indent);
    let result = '';

    if (Array.isArray(obj)) {
      obj.forEach(item => {
        if (item === null || item === undefined) return;
        if (typeof item === 'object' && !Array.isArray(item)) {
          const keys = Object.keys(item);
          if (keys.length === 0) return;
          result += `${spaces}- ${keys[0]}: ${this.yamlValue(item[keys[0]], indent + 1)}\n`;
          keys.slice(1).forEach(k => {
            result += `${spaces}  ${k}: ${this.yamlValue(item[k], indent + 1)}\n`;
          });
        } else {
          result += `${spaces}- ${this.yamlValue(item, indent)}\n`;
        }
      });
    } else if (typeof obj === 'object' && obj !== null) {
      Object.keys(obj).forEach(key => {
        const val = obj[key];
        if (val === null || val === undefined) return;
        // Skip empty objects (like headers: {})
        if (typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length === 0) return;
        if (typeof val === 'object') {
          result += `${spaces}${key}:\n`;
          result += this.toYaml(val, indent + 1);
        } else {
          result += `${spaces}${key}: ${this.yamlValue(val, indent)}\n`;
        }
      });
    }

    return result;
  },

  yamlValue(val, indent) {
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (typeof val === 'number') return val.toString();
    if (typeof val === 'string') {
      if (/[:{}\[\],&*?|>!%@`#]/.test(val) || val === '' || val === 'true' || val === 'false' || val === 'null' || /^\d/.test(val)) {
        return `"${val.replace(/"/g, '\\"')}"`;
      }
      return val;
    }
    if (typeof val === 'object' && val !== null) {
      return '\n' + this.toYaml(val, indent + 1);
    }
    return String(val);
  },

  // --- VMess WS Reverse ---
  applyVmessReverse(proxy) {
    // Common ISP bypass: swap path and host in ws-opts
    if (proxy.type === 'vmess' && proxy.network === 'ws' && proxy['ws-opts']) {
      const wsOpts = proxy['ws-opts'];
      const originalHost = wsOpts.headers && wsOpts.headers.Host;
      const originalPath = wsOpts.path;

      // Reverse: use path prefix as if it's the actual routing path
      if (originalHost && originalPath && originalPath !== '/') {
        // Some configs use path as the real destination indicator
        // This trick helps bypass ISP DPI that blocks specific WS paths
        const reversedPath = '/' + originalHost.replace(/\./g, '/') + originalPath;
        wsOpts.path = reversedPath;
        delete wsOpts.headers.Host;
      }
    }
  },

  // --- Format proxy order ---
  applyProxyFormat(proxies, format) {
    if (format === 'top') {
      // Format Atas: proxy names listed first in groups, then type info
      // Just reverse the proxy order for group listing
      return [...proxies].reverse();
    }
    return proxies;
  },

  // --- Full config generator ---
  generateConfig(proxies, options = {}) {
    const configType = options.configType || 'standard-redir';
    const proxyFormat = options.proxyFormat || 'bottom';
    const proxyProvider = options.proxyProvider || false;
    const subUrl = options.subUrl || '';
    const customRules = options.customRules || '';
    const vmessReverse = options.vmessReverse || false;

    // Apply vmess reverse if enabled
    if (vmessReverse) {
      proxies.forEach(p => this.applyVmessReverse(p));
    }

    // Apply proxy format ordering
    const orderedProxies = this.applyProxyFormat(proxies, proxyFormat);
    const proxyNames = orderedProxies.map(p => p.name);

    const dnsMode = configType === 'standard-fakeip' ? 'fake-ip' : 'redir-host';

    const config = {
      'mixed-port': 7890,
      'port': 7891,
      'socks-port': 7892,
      'redir-port': 7893,
      'allow-lan': true,
      'mode': 'rule',
      'log-level': 'info',
      'ipv6': false,
      'external-controller': '0.0.0.0:9090',
      'external-ui': '/usr/share/openclash/ui',
      'secret': '',
    };

    // DNS
    config.dns = {
      enable: true,
      ipv6: false,
      'enhanced-mode': dnsMode,
      'fake-ip-range': '198.18.0.1/16',
      nameserver: ['8.8.8.8', '1.1.1.1', '114.114.114.114'],
      fallback: ['tls://8.8.8.8:853', 'tls://1.1.1.1:853'],
    };

    // Fake-ip DNS settings
    if (dnsMode === 'fake-ip') {
      config.dns['fake-ip-filter'] = [
        '*.lan',
        'localhost.ptlogin2.qq.com',
        '+.srv.nintendo.net',
        '+.stun.playstation.net',
        'xbox.*.microsoft.com',
        '+.xboxlive.com',
        '+.ntp.org',
      ];
    }

    // Clash.Meta specific settings
    if (configType === 'meta') {
      config['unified-delay'] = true;
      config['tcp-concurrent'] = true;
      config['find-process-mode'] = 'strict';
      config.sniffer = {
        enable: true,
        'force-domain': ['+.netflix.com', '+.nflxvideo.net'],
        'parse-pure-ip': true,
        sniff: { HTTP: { ports: [80, '8080'] }, TLS: { ports: [443, '8443'] } },
      };
    }

    // Proxies
    config.proxies = orderedProxies;

    // Proxy groups
    config['proxy-groups'] = [
      { name: 'PROXY', type: 'select', proxies: [...proxyNames, 'DIRECT', 'REJECT'] },
      { name: 'Streaming', type: 'select', proxies: [...proxyNames, 'PROXY', 'DIRECT'] },
      { name: 'AdBlock', type: 'select', proxies: ['REJECT', 'DIRECT', 'PROXY'] },
      { name: 'Auto', type: 'url-test', proxies: proxyNames, url: 'http://www.gstatic.com/generate_204', interval: 300 },
    ];

    // Proxy provider
    if (proxyProvider && subUrl) {
      config['proxy-providers'] = {
        'my-provider': {
          type: 'http',
          path: './proxy_provider.yaml',
          url: subUrl,
          interval: 3600,
          'health-check': {
            enable: true,
            url: 'http://www.gstatic.com/generate_204',
            interval: 300,
          },
        },
      };
    }

    // Rules - Indonesian user focused
    const rules = [
      'DOMAIN-SUFFIX,google.com,PROXY',
      'DOMAIN-SUFFIX,google.co.id,PROXY',
      'DOMAIN-SUFFIX,youtube.com,PROXY',
      'DOMAIN-SUFFIX,ytimg.com,PROXY',
      'DOMAIN-SUFFIX,yt3.ggpht.com,PROXY',
      'DOMAIN-SUFFIX,github.com,PROXY',
      'DOMAIN-SUFFIX,githubusercontent.com,PROXY',
      'DOMAIN-SUFFIX,telegram.org,PROXY',
      'DOMAIN-SUFFIX,t.me,PROXY',
      'DOMAIN-SUFFIX,telegram.me,PROXY',
      'DOMAIN-SUFFIX,whatsapp.net,PROXY',
      'DOMAIN-SUFFIX,wa.me,PROXY',
      'DOMAIN-SUFFIX,whatsapp.com,PROXY',
      'DOMAIN-SUFFIX,netflix.com,PROXY',
      'DOMAIN-SUFFIX,nflxvideo.net,PROXY',
      'DOMAIN-SUFFIX,nflximg.net,PROXY',
      'DOMAIN-SUFFIX,nflximg.com,PROXY',
      'DOMAIN-SUFFIX,spotify.com,PROXY',
      'DOMAIN-SUFFIX,scdn.co,PROXY',
      'DOMAIN-KEYWORD,google,PROXY',
      'DOMAIN-KEYWORD,youtube,PROXY',
      'DOMAIN-KEYWORD,telegram,PROXY',
      'DOMAIN-KEYWORD,whatsapp,PROXY',
      'DOMAIN-KEYWORD,netflix,PROXY',
      'DOMAIN-SUFFIX,ad.com,AdBlock',
      'DOMAIN-SUFFIX,adservice.google.com,AdBlock',
      'DOMAIN-SUFFIX,pagead2.googlesyndication.com,AdBlock',
      'DOMAIN-KEYWORD,adservice,AdBlock',
      'DOMAIN-KEYWORD,adsrv,AdBlock',
      'GEOIP,ID,DIRECT',
      'GEOIP,CN,DIRECT',
      'MATCH,PROXY',
    ];

    // Add custom rules at the top
    if (customRules) {
      customRules.split('\n').forEach(r => {
        r = r.trim();
        if (r && !r.startsWith('#')) rules.unshift(r);
      });
    }

    config.rules = rules;

    return config;
  },

  // --- Parse subscription URL content ---
  parseSubscriptionContent(content) {
    let lines = content;
    try {
      const decoded = atob(content.trim());
      if (decoded.includes('://')) lines = decoded;
    } catch (e) {
      // Not base64, use as-is
    }

    const uris = [];
    lines.split(/[\n|]/).forEach(line => {
      line = line.trim();
      if (line.includes('://')) uris.push(line);
    });

    return uris;
  },
};

// Export for both browser and Node
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Converter;
}
