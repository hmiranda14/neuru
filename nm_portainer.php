<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Portainer REST client (server-side only). The API key is decrypted from
// nm_settings and never reaches the browser. Every call returns a normalized
// envelope so callers degrade gracefully instead of throwing:
//   ['ok'=>bool, 'status'=>int, 'data'=>mixed, 'error'=>string]
// Settings keys: portainer_url, portainer_api_key (encrypted), portainer_verify_ssl,
// portainer_host_map.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_secrets.php';

if (!function_exists('nm_portainer_cfg')) {

    function nm_portainer_cfg($conn): array {
        $cfg = ['url' => '', 'key' => '', 'verify' => true, 'host_map' => []];
        if (!($conn instanceof mysqli)) return $cfg;
        $r = @$conn->query("SELECT setting_key, setting_val FROM nm_settings
            WHERE setting_key IN ('portainer_url','portainer_api_key','portainer_verify_ssl','portainer_host_map')");
        if ($r) while ($row = $r->fetch_assoc()) {
            switch ($row['setting_key']) {
                case 'portainer_url':        $cfg['url']    = rtrim($row['setting_val'], '/'); break;
                case 'portainer_api_key':    $cfg['key']    = nm_secret_decrypt($row['setting_val']); break;
                case 'portainer_verify_ssl': $cfg['verify'] = $row['setting_val'] !== '0'; break;
                case 'portainer_host_map':   $cfg['host_map'] = nm_portainer_parse_host_map($row['setting_val']); break;
            }
        }
        return $cfg;
    }

    function nm_portainer_configured(array $cfg): bool {
        return $cfg['url'] !== '' && $cfg['key'] !== '';
    }

    function nm_portainer_parse_host_map(string $raw): array {
        $out = [];
        foreach (preg_split('/\r?\n/', $raw) as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '=') === false) continue;
            [$k, $v] = explode('=', $line, 2);
            $k = strtolower(trim($k)); $v = trim($v);
            if ($k !== '' && $v !== '') $out[$k] = $v;
        }
        return $out;
    }

    // Core transport. Returns the normalized envelope.
    function nm_portainer_call(array $cfg, string $method, string $path, $body = null, int $timeout = 30): array {
        if (!nm_portainer_configured($cfg)) return ['ok'=>false,'status'=>0,'data'=>null,'error'=>'Portainer not configured'];
        $url = $cfg['url'] . $path;
        $ch  = curl_init($url);
        $headers = ['X-API-Key: ' . $cfg['key'], 'Accept: application/json'];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => max(2, $timeout),
            CURLOPT_SSL_VERIFYPEER => $cfg['verify'],
            CURLOPT_SSL_VERIFYHOST => $cfg['verify'] ? 2 : 0,
        ];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $opts[CURLOPT_POSTFIELDS] = is_string($body) ? $body : json_encode($body);
        }
        $opts[CURLOPT_HTTPHEADER] = $headers;
        curl_setopt_array($ch, $opts);
        $resp = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr = curl_error($ch);
        curl_close($ch);

        if ($resp === false) return ['ok'=>false,'status'=>0,'data'=>null,'error'=>($cerr ?: 'Connection failed')];
        if ($code === 204 || $resp === '') {
            $data = [];
        } else {
            $data = json_decode($resp, true);
            if ($data === null && $resp !== 'null') $data = $resp;  // non-JSON body
        }
        if ($code >= 200 && $code < 300) return ['ok'=>true,'status'=>$code,'data'=>$data,'error'=>''];
        // error path — try to surface Portainer's message
        $msg = is_array($data) ? ($data['message'] ?? ($data['detail'] ?? ($data['error'] ?? ''))) : (is_string($data) ? $data : '');
        if ($code === 401 || $code === 403) $msg = 'Authentication failed — check the API key.';
        if ($msg === '') $msg = "HTTP {$code}";
        return ['ok'=>false,'status'=>$code,'data'=>$data,'error'=>$msg];
    }

    if (!defined('NM_PORTAINER_ACTIONS')) define('NM_PORTAINER_ACTIONS', ['start','stop','restart','kill','pause','unpause']);

    function nm_portainer_ping(array $cfg): array {
        $r = nm_portainer_call($cfg, 'GET', '/api/system/status');
        if (!$r['ok']) $r = nm_portainer_call($cfg, 'GET', '/api/status');   // older fallback
        if (!$r['ok']) return $r;
        $ver = is_array($r['data']) ? ($r['data']['Version'] ?? ($r['data']['version'] ?? '')) : '';
        // confirm the key actually authenticates against a protected endpoint
        $e = nm_portainer_call($cfg, 'GET', '/api/endpoints?limit=1');
        if (!$e['ok']) return $e;
        return ['ok'=>true,'status'=>200,'data'=>['version'=>$ver],'error'=>''];
    }

    // Create + start a container from an image, via the Portainer→Docker proxy.
    // (Portainer was monitor-only before this; this adds the one write path the
    //  WireGuard orchestrator + canary deployer need.)
    //   $spec = ['name','image','env'[],'ports'{cport=>hport},'caps'[],'sysctls'{},'binds'[],'restart']
    // Returns the standard ['ok','status','data','error'] envelope; data.Id on success.
    function nm_portainer_container_create(array $cfg, int $eid, array $spec): array {
        if (!nm_portainer_configured($cfg)) return ['ok'=>false,'status'=>0,'data'=>null,'error'=>'Portainer not configured'];
        $image = trim((string)($spec['image'] ?? ''));
        if ($image === '') return ['ok'=>false,'status'=>0,'data'=>null,'error'=>'image required'];

        // 1) pull the image (best-effort; create still works if it is already present)
        [$repo, $tag] = strpos($image, ':') !== false ? explode(':', $image, 2) : [$image, 'latest'];
        nm_portainer_call($cfg, 'POST',
            "/api/endpoints/{$eid}/docker/images/create?fromImage=".rawurlencode($repo)."&tag=".rawurlencode($tag),
            '', 180);

        // 2) build the Docker create body
        $exposed = []; $bindings = [];
        foreach (($spec['ports'] ?? []) as $cport => $hport) {
            $cport = (string)$cport;
            if (strpos($cport, '/') === false) $cport .= '/tcp';
            $exposed[$cport] = new stdClass();
            $bindings[$cport] = [['HostPort' => (string)$hport]];
        }
        $body = [
            'Image'        => $image,
            'Env'          => array_values($spec['env'] ?? []),
            'ExposedPorts' => $exposed ? $exposed : new stdClass(),
            'HostConfig'   => [
                'Binds'         => array_values($spec['binds'] ?? []),
                'PortBindings'  => $bindings ? $bindings : new stdClass(),
                'CapAdd'        => array_values($spec['caps'] ?? []),
                'Sysctls'       => (object)($spec['sysctls'] ?? []),
                'RestartPolicy' => ['Name' => $spec['restart'] ?? 'unless-stopped'],
            ],
        ];
        $name = rawurlencode((string)($spec['name'] ?? ''));
        $r = nm_portainer_call($cfg, 'POST', "/api/endpoints/{$eid}/docker/containers/create?name={$name}", $body, 60);
        if (!$r['ok']) return $r;
        $cid = is_array($r['data']) ? ($r['data']['Id'] ?? '') : '';
        if ($cid === '') return ['ok'=>false,'status'=>$r['status'],'data'=>$r['data'],'error'=>'create returned no container Id'];

        // 3) start it (204 = started, 304 = already running)
        $s = nm_portainer_call($cfg, 'POST', "/api/endpoints/{$eid}/docker/containers/{$cid}/start", null, 30);
        if (!$s['ok'] && !in_array($s['status'], [204, 304], true)) return $s;
        return ['ok'=>true,'status'=>201,'data'=>['Id'=>$cid,'name'=>$spec['name'] ?? ''],'error'=>''];
    }

    function nm_portainer_endpoints(array $cfg): array { return nm_portainer_call($cfg, 'GET', '/api/endpoints?limit=200'); }
    function nm_portainer_endpoint(array $cfg, int $id): array { return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$id}"); }
    function nm_portainer_containers(array $cfg, int $eid, bool $all = true, int $timeout = 12): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/containers/json?all=" . ($all ? '1' : '0'), null, $timeout);
    }
    function nm_portainer_engine_info(array $cfg, int $eid, int $timeout = 10): array { return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/info", null, $timeout); }
    function nm_portainer_container_action(array $cfg, int $eid, string $cid, string $action): array {
        $action = strtolower($action);
        if (!in_array($action, NM_PORTAINER_ACTIONS, true)) return ['ok'=>false,'status'=>422,'data'=>null,'error'=>'Invalid action'];
        $r = nm_portainer_call($cfg, 'POST', "/api/endpoints/{$eid}/docker/containers/{$cid}/{$action}");
        if (!$r['ok'] && in_array($r['status'], [204,304], true)) $r['ok'] = true;   // already in state
        return $r;
    }
    // Remove (uninstall) a container. $force removes a running one (Docker refuses otherwise → 409);
    // $volumes also deletes the container's anonymous volumes. 204 = removed, 404 = already gone (OK).
    function nm_portainer_container_remove(array $cfg, int $eid, string $cid, bool $force = false, bool $volumes = false): array {
        $q = '?force=' . ($force ? 'true' : 'false') . '&v=' . ($volumes ? 'true' : 'false');
        $r = nm_portainer_call($cfg, 'DELETE', "/api/endpoints/{$eid}/docker/containers/" . rawurlencode($cid) . $q, null, 30);
        if (!$r['ok'] && in_array($r['status'], [204,404], true)) $r['ok'] = true;   // 404 = nothing to remove
        return $r;
    }
    // $oneShot=true → Docker returns a single sample immediately (no ~1-2s wait for
    // the CPU delta cycle). Use it when you only need the cumulative counters
    // (network/blkio); CPU% will read 0 since there's no precpu sample.
    function nm_portainer_container_stats(array $cfg, int $eid, string $cid, int $timeout = 30, bool $oneShot = false): array {
        $q = 'stream=false' . ($oneShot ? '&one-shot=true' : '');
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/containers/{$cid}/stats?{$q}", null, $timeout);
    }
    function nm_portainer_container_inspect(array $cfg, int $eid, string $cid, bool $size = false): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/containers/{$cid}/json" . ($size ? '?size=true' : ''));
    }
    function nm_portainer_container_top(array $cfg, int $eid, string $cid): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/containers/{$cid}/top?ps_args=aux");
    }
    function nm_portainer_system_df(array $cfg, int $eid): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/system/df");
    }

    // ── Images ────────────────────────────────────────────────────────────────
    function nm_portainer_images(array $cfg, int $eid): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/images/json?all=0");
    }
    function nm_portainer_image_remove(array $cfg, int $eid, string $id, bool $force = false): array {
        $q = '?force=' . ($force ? 'true' : 'false') . '&noprune=false';
        return nm_portainer_call($cfg, 'DELETE', "/api/endpoints/{$eid}/docker/images/" . rawurlencode($id) . $q);
    }
    // Prune images. $all=false → dangling only (safe); $all=true → every image not
    // used by a container (Docker filter dangling=false).
    function nm_portainer_images_prune(array $cfg, int $eid, bool $all = false): array {
        $q = $all ? '?filters=' . rawurlencode('{"dangling":["false"]}') : '';
        return nm_portainer_call($cfg, 'POST', "/api/endpoints/{$eid}/docker/images/prune{$q}");
    }

    // ── Networks ──────────────────────────────────────────────────────────────
    function nm_portainer_networks(array $cfg, int $eid): array {
        return nm_portainer_call($cfg, 'GET', "/api/endpoints/{$eid}/docker/networks");
    }

    // Resolve the real Docker host IP for an endpoint (for SSH targets):
    //   host_map override (by name) → tcp://IP from endpoint URL → //IP from the
    //   Portainer base URL (local/agent endpoints) → ''.
    function nm_portainer_host_ip(array $cfg, int $eid, string $hostName = ''): string {
        $map = $cfg['host_map'] ?? [];
        if ($hostName !== '' && isset($map[strtolower($hostName)])) return $map[strtolower($hostName)];
        $e = nm_portainer_endpoint($cfg, $eid);
        if ($e['ok'] && is_array($e['data'])) {
            $name = $e['data']['Name'] ?? ''; $url = $e['data']['URL'] ?? ''; $type = (int)($e['data']['Type'] ?? 0);
            if ($name !== '' && isset($map[strtolower($name)])) return $map[strtolower($name)];
            if (preg_match('#tcp://([\d.]+)#', $url, $m)) return $m[1];
            if ($type === 1 && preg_match('#//([\d.]+)#', $cfg['url'], $m)) return $m[1];  // local agent → Portainer host
        }
        if (preg_match('#//([\d.]+)#', $cfg['url'], $m)) return $m[1];   // last resort: the Portainer host
        return '';
    }

    // ── Normalizers ───────────────────────────────────────────────────────────
    function nm_portainer_norm_endpoints($data): array {
        $out = [];
        foreach ((array)$data as $e) {
            $snap = $e['Snapshots'][0] ?? null;
            $out[] = [
                'id'   => (int)($e['Id'] ?? 0),
                'name' => $e['Name'] ?? ('env ' . ($e['Id'] ?? '')),
                'kind' => (int)($e['Type'] ?? 0),
                'up'   => $snap ? ((int)($snap['Snapshot']['Running'] ?? $snap['DockerSnapshotRaw']['Running'] ?? 1) >= 0 && ($e['Status'] ?? 1) == 1) : (($e['Status'] ?? 1) == 1),
            ];
        }
        return $out;
    }
    // endpoint_id → {name, ip, up} for the whole Portainer fleet (cached per request).
    // Lets any page turn a container incident's endpoint_id into the real Docker HOST it
    // runs on, instead of showing the container name / a blank host.
    function nm_portainer_endpoint_map(array $cfg): array {
        static $cache = null; if ($cache !== null) return $cache;
        $cache = [];
        if (!nm_portainer_configured($cfg)) return $cache;
        $e = nm_portainer_endpoints($cfg);
        if (!$e['ok']) return $cache;
        foreach (nm_portainer_norm_endpoints($e['data']) as $x) {
            $ip = nm_portainer_host_ip($cfg, (int)$x['id'], (string)$x['name']);
            $cache[(int)$x['id']] = ['name'=>$x['name'], 'ip'=>$ip, 'up'=>$x['up']];
        }
        return $cache;
    }
    function nm_portainer_norm_container($c): array {
        $name = '';
        if (!empty($c['Names'][0])) $name = ltrim($c['Names'][0], '/');
        $ports = [];
        foreach (($c['Ports'] ?? []) as $p) {
            $ports[] = (isset($p['PublicPort']) ? ($p['PublicPort'].'→') : '') . ($p['PrivatePort'] ?? '') . '/' . ($p['Type'] ?? 'tcp');
        }
        $labels = $c['Labels'] ?? [];
        return [
            'cid'     => $c['Id'] ?? '',
            'name'    => $name,
            'image'   => $c['Image'] ?? '',
            'state'   => strtolower($c['State'] ?? ''),
            'status'  => $c['Status'] ?? '',
            'ports'   => $ports,
            'stack'   => $labels['com.docker.compose.project'] ?? '',
            'created' => (int)($c['Created'] ?? 0),
        ];
    }
    function nm_portainer_summarize(array $containers): array {
        $s = ['total'=>0,'running'=>0,'stopped'=>0,'paused'=>0,'restarting'=>0,'unhealthy'=>0,'other'=>0];
        foreach ($containers as $c) {
            $s['total']++;
            $st = $c['state'];
            if     ($st === 'running')    $s['running']++;
            elseif ($st === 'exited' || $st === 'dead' || $st === 'created') $s['stopped']++;
            elseif ($st === 'paused')     $s['paused']++;
            elseif ($st === 'restarting') $s['restarting']++;
            else                          $s['other']++;
            if (stripos($c['status'], 'unhealthy') !== false) $s['unhealthy']++;
        }
        return $s;
    }
    // Normalize images from system/df (it carries per-image container usage), with
    // a fallback to images/json when df gives no Images array.
    function nm_portainer_norm_images($dfData, $imagesJson = null): array {
        $rows = []; $sum = ['total'=>0,'in_use'=>0,'unused'=>0,'dangling'=>0,'reclaimable'=>0,'size'=>0];
        $src = is_array($dfData) && !empty($dfData['Images']) ? $dfData['Images'] : (array)$imagesJson;
        foreach ($src as $im) {
            $tags = $im['RepoTags'] ?? [];
            $tags = array_values(array_filter((array)$tags, fn($t)=>$t && $t !== '<none>:<none>'));
            $dangling = empty($tags);
            $name = $dangling ? '<none>' : $tags[0];
            // df uses Containers (count); images/json has no usage → treat as unknown (-1)
            $containers = array_key_exists('Containers', $im) ? (int)$im['Containers'] : -1;
            $size  = (int)($im['Size'] ?? 0);
            $shared = (int)($im['SharedSize'] ?? 0);
            $uniq  = max(0, $size - max(0,$shared));         // space actually reclaimed if removed
            $inUse = $containers > 0;
            $rows[] = [
                'id'=>$im['Id'] ?? '', 'name'=>$name, 'tags'=>$tags, 'dangling'=>$dangling,
                'size'=>$size, 'shared'=>$shared, 'reclaim'=>$uniq, 'containers'=>$containers,
                'in_use'=>$inUse, 'created'=>(int)($im['Created'] ?? 0),
            ];
            $sum['total']++; $sum['size'] += $size;
            if ($dangling) $sum['dangling']++;
            if ($inUse) $sum['in_use']++; else { $sum['unused']++; $sum['reclaimable'] += $uniq; }
        }
        usort($rows, fn($a,$b)=>[$a['in_use']?1:0,-$a['reclaim']]<=>[$b['in_use']?1:0,-$b['reclaim']]);
        return [$rows, $sum];
    }
    function nm_portainer_engine($data): ?array {
        if (!is_array($data)) return null;
        return [
            'name'    => $data['Name'] ?? '',
            'version'  => $data['ServerVersion'] ?? '',
            'os'      => trim(($data['OperatingSystem'] ?? '') . ' ' . ($data['Architecture'] ?? '')),
            'cpus'    => (int)($data['NCPU'] ?? 0),
            'memory'  => (int)($data['MemTotal'] ?? 0),
            'images'  => (int)($data['Images'] ?? 0),
        ];
    }
    // CPU% (Docker delta math) + memory from a one-shot stats sample.
    function nm_portainer_norm_stats($d): array {
        $out = ['cpu_pct'=>0,'mem_pct'=>0,'mem_used'=>0,'mem_limit'=>0,'mem_used_b'=>0,
                'net_rx'=>0,'net_tx'=>0,'blk_read'=>0,'blk_write'=>0,'pids'=>0];
        if (!is_array($d)) return $out;
        $cpu = $d['cpu_stats'] ?? []; $pre = $d['precpu_stats'] ?? [];
        $cd = ($cpu['cpu_usage']['total_usage'] ?? 0) - ($pre['cpu_usage']['total_usage'] ?? 0);
        $sd = ($cpu['system_cpu_usage'] ?? 0) - ($pre['system_cpu_usage'] ?? 0);
        $ncpu = $cpu['online_cpus'] ?? (count($cpu['cpu_usage']['percpu_usage'] ?? []) ?: 1);
        if ($sd > 0 && $cd > 0) $out['cpu_pct'] = round($cd / $sd * $ncpu * 100, 2);
        $mem = $d['memory_stats'] ?? [];
        $usage = (int)($mem['usage'] ?? 0);
        $cache = (int)($mem['stats']['inactive_file'] ?? $mem['stats']['cache'] ?? 0);
        $used  = max(0, $usage - $cache);
        $limit = (int)($mem['limit'] ?? 0);
        $out['mem_used_b'] = $used; $out['mem_limit'] = $limit;
        $out['mem_used']   = $used;
        if ($limit > 0) $out['mem_pct'] = round($used / $limit * 100, 2);
        foreach (($d['networks'] ?? []) as $n) { $out['net_rx'] += (int)($n['rx_bytes'] ?? 0); $out['net_tx'] += (int)($n['tx_bytes'] ?? 0); }
        foreach (($d['blkio_stats']['io_service_bytes_recursive'] ?? []) as $b) {
            if (strtolower($b['op'] ?? '') === 'read')  $out['blk_read']  += (int)($b['value'] ?? 0);
            if (strtolower($b['op'] ?? '') === 'write') $out['blk_write'] += (int)($b['value'] ?? 0);
        }
        $out['pids'] = (int)($d['pids_stats']['current'] ?? 0);
        return $out;
    }
}
