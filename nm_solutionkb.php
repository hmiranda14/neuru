<?php
// ─────────────────────────────────────────────────────────────────────────────
// NetMon — Solution Knowledge Base (RAG) for the container fix flow. Wraps
// container_kb + the kb_ingest_url / kb_search_url / books_search_url webhooks.
// Best-effort: never throws. Auth to n8n uses the shared X-NetMon-Token.
// ─────────────────────────────────────────────────────────────────────────────
require_once __DIR__ . '/nm_n8n.php';

if (!function_exists('nm_kb_capture')) {

    function _kb_set($conn,$k,$d=''){ $r=$conn->query("SELECT setting_val FROM nm_settings WHERE setting_key='".$conn->real_escape_string($k)."' LIMIT 1"); return $r&&($x=$r->fetch_row())?$x[0]:$d; }
    function _kb_norm_err(string $e): string { // mirrors nm_normalize_error
        $x=strtolower(trim($e));
        $x=preg_replace('/\d{4}-\d{2}-\d{2}[t ][\d:.]+z?/','#ts',$x)??$x;
        $x=preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/','#ip',$x)??$x;
        $x=preg_replace('/\b[0-9a-f]{8,}\b/','#hex',$x)??$x;
        $x=preg_replace('/\b\d+\b/','#n',$x)??$x; $x=preg_replace('/\s+/',' ',$x)??$x;
        return substr(trim($x),0,800);
    }
    // Guarded independently: nm_containers_api.php declares its own nm_kb_doc()
    // at top level, and the fix_* endpoints require this file afterwards — without
    // this guard that path fatals with "Cannot redeclare nm_kb_doc()".
    if (!function_exists('nm_kb_doc')) {
    function nm_kb_doc(array $r): string {
        return substr("Subject: ".($r['container_name']??'')."\nSeverity: ".($r['severity']??'')
            ."\n\nProblem:\n".($r['error_text']??'')."\n\nSummary:\n".($r['summary']??'')
            ."\n\nResolution:\n".($r['resolution']??'')."\n\nSession transcript:\n".($r['transcript']??''), 0, 14000);
    }
    }
    function _kb_base(): string { return ((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https':'http').'://'.($_SERVER['HTTP_HOST']??'localhost'); }
    function _kb_post($conn, string $url, array $payload, int $timeout=8): ?array {
        if ($url === '' || !function_exists('curl_init')) return null;
        $cfg = nm_n8n_get($conn);
        if(function_exists('nm_n8n_neuru_stamp'))$payload=nm_n8n_neuru_stamp($conn,$payload,$url);  // hosted-flow gatecheck
        $ch = curl_init($url);
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($payload),
            CURLOPT_CONNECTTIMEOUT=>4,CURLOPT_TIMEOUT=>$timeout,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>false,
            CURLOPT_HTTPHEADER=>['Content-Type: application/json','X-NetMon-Token: '.$cfg['inbound_token']]]);
        $body=curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); curl_close($ch);
        if ($body===false || $code>=400) return null;
        $j=json_decode($body,true); return is_array($j)?$j:[];
    }

    // Build the full resolution write-up from a Solution Commander session: the
    // human note (if any), the actual commands run, and the AI closing summary —
    // not just whatever was typed in the resolve box. Falls back to note/ai when
    // there was no command session (e.g. resolved straight from Error Watch).
    function nm_kb_build_resolution($conn, int $id, string $note = '', string $aiSolution = ''): string {
        $cmds = [];
        $r = $conn->query("SELECT line FROM container_fix_logs WHERE incident_id=".(int)$id." AND level='cmd' ORDER BY id ASC");
        if ($r) while ($x = $r->fetch_row()) { $l = trim((string)$x[0]); if ($l !== '') $cmds[] = (strncmp($l,'$ ',2)===0 ? $l : '$ '.$l); }
        // Closing summary line, if the loop posted one (level 'done', strip the ✓/✗ marker).
        $done = '';
        $r = $conn->query("SELECT line FROM container_fix_logs WHERE incident_id=".(int)$id." AND level='done' ORDER BY id DESC LIMIT 1");
        if ($r && ($x = $r->fetch_row())) $done = trim(preg_replace('/^[✓✗]\s*/u','',(string)$x[0]));

        $parts = [];
        $head = trim($note) !== '' ? trim($note) : trim($aiSolution);
        if ($head !== '') $parts[] = $head;
        if ($cmds) $parts[] = "Commands run:\n".implode("\n", $cmds);
        if ($done !== '' && $done !== $head) $parts[] = "Outcome:\n".$done;
        $out = trim(implode("\n\n", $parts));
        return $out !== '' ? $out : 'Resolved.';
    }

    // Snapshot a resolved problem into container_kb + ship to n8n. Returns kb id.
    // $push=false stores the KB row locally but SKIPS the synchronous n8n vector push (which can block
    // 4–8s per call if the kb-ingest webhook is slow/unreachable). Un-vectorized rows (vectorized_at IS
    // NULL) are re-pushable from the Knowledge Base page. Bulk resolve passes false so a "resolve all"
    // never hangs the request on N slow webhook calls.
    function nm_kb_capture($conn, array $e, bool $push=true): ?int {
        if (_kb_set($conn,'kb_enabled','1')==='0') return null;
        $subject = trim((string)($e['subject'] ?? ''));
        $error   = (string)($e['error'] ?? '');
        $fp = (string)($e['fingerprint'] ?? '') ?: sha1(strtolower($subject).'|'._kb_norm_err($error));
        $summary=(string)($e['summary']??''); $resolution=(string)($e['resolution']??''); $transcript=(string)($e['transcript']??'');
        $chash = sha1($error."\x1f".$summary."\x1f".$resolution."\x1f".$transcript);
        $image=(string)($e['image']??''); $sev=(string)($e['severity']??''); $src=(string)($e['source']??'resolve');
        $iid = isset($e['incident_id']) ? (int)$e['incident_id'] : null;
        // dedup by (fingerprint, container_name)
        $q=$conn->prepare("SELECT id FROM container_kb WHERE fingerprint=? AND container_name=? LIMIT 1");
        $q->bind_param('ss',$fp,$subject); $q->execute(); $ex=$q->get_result()->fetch_assoc();
        if ($ex) {
            $kbId=(int)$ex['id'];
            $st=$conn->prepare("UPDATE container_kb SET image=?,severity=?,error_text=?,summary=?,resolution=?,transcript=?,content_hash=?,source=?,vectorized_at=NULL WHERE id=?");
            $st->bind_param('ssssssssi',$image,$sev,$error,$summary,$resolution,$transcript,$chash,$src,$kbId); $st->execute();
        } else {
            $st=$conn->prepare("INSERT INTO container_kb(incident_id,container_name,image,severity,error_text,fingerprint,summary,resolution,transcript,content_hash,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
            $st->bind_param('issssssssss',$iid,$subject,$image,$sev,$error,$fp,$summary,$resolution,$transcript,$chash,$src); $st->execute();
            $kbId=$conn->insert_id;
        }
        if ($push) nm_kb_push($conn,$kbId);
        return $kbId;
    }

    function nm_kb_push($conn, int $kbId): bool {
        $url=_kb_set($conn,'kb_ingest_url',''); if($url==='') return false;
        $r=$conn->query("SELECT * FROM container_kb WHERE id={$kbId} LIMIT 1"); $row=$r?$r->fetch_assoc():null;
        if(!$row) return false;
        $payload=['kb_id'=>(int)$row['id'],'incident_id'=>$row['incident_id'],'container_name'=>$row['container_name'],
            'image'=>$row['image'],'severity'=>$row['severity'],'fingerprint'=>$row['fingerprint'],'source'=>$row['source'],
            'content_hash'=>$row['content_hash'],'summary'=>$row['summary'],'resolution'=>$row['resolution'],'error'=>$row['error_text'],
            'text'=>nm_kb_doc($row),'vectorized_url'=>_kb_base().'/nm_containers_api.php?ep=kb_vectorized&id='.$row['id']];
        return _kb_post($conn,$url,$payload,10) !== null;
    }

    // Vector search; drop below kb_min_score; hydrate from container_kb; bump reuse_count.
    function nm_kb_search($conn, string $query, array $ctx=[]): array {
        $url=_kb_set($conn,'kb_search_url',''); if($url==='') return [];
        $topk=(int)_kb_set($conn,'kb_top_k','3') ?: 3; $minScore=(float)_kb_set($conn,'kb_min_score','0.5');
        $resp=_kb_post($conn,$url,['query'=>substr($query,0,2000),'container_name'=>$ctx['container_name']??'','severity'=>$ctx['severity']??'','top_k'=>$topk],8);
        if($resp===null) return [];
        $matches=$resp['matches']??($resp['results']??(array_is_list($resp)?$resp:[]));
        $out=[];
        foreach((array)$matches as $m){
            $kbId=(int)($m['kb_id']??($m['id']??0)); if(!$kbId) continue;
            $score=isset($m['score'])?(float)$m['score']:null;
            if($score!==null && $score<$minScore) continue;
            $r=$conn->query("SELECT id,container_name,error_text,summary,resolution FROM container_kb WHERE id={$kbId} LIMIT 1");
            $row=$r?$r->fetch_assoc():null; if(!$row) continue;
            $conn->query("UPDATE container_kb SET reuse_count=reuse_count+1 WHERE id={$kbId}");
            $out[]=['kb_id'=>$kbId,'score'=>$score,'container_name'=>$row['container_name'],'error'=>$row['error_text'],
                    'summary'=>$row['summary'],'resolution'=>$row['resolution']];
        }
        return $out;
    }

    function nm_kb_search_books($conn, string $query): array {
        $url=_kb_set($conn,'books_search_url',''); if($url==='') return [];
        $topk=(int)_kb_set($conn,'books_top_k','3') ?: 3;
        $resp=_kb_post($conn,$url,['query'=>substr($query,0,2000),'top_k'=>$topk],8);
        if($resp===null) return [];
        $matches=$resp['matches']??($resp['results']??(array_is_list($resp)?$resp:[]));
        $out=[]; foreach((array)$matches as $m) $out[]=['book'=>$m['book']??'','title'=>$m['title']??'','url'=>$m['url']??'','score'=>$m['score']??null,'text'=>$m['text']??''];
        return $out;
    }

    // "REFERENCE ONLY" block, tagging SAME SYSTEM vs different system.
    function nm_kb_context(array $matches, string $activeSubject=''): string {
        if(!$matches) return '';
        $s="REFERENCE ONLY — past solutions (do not blindly apply another system's fix):\n";
        foreach($matches as $m){
            $same=(strtolower($m['container_name']??'')===strtolower($activeSubject))?'SAME SYSTEM':('different system: '.($m['container_name']??'?'));
            $s.="\n[{$same}] ".($m['summary']?:$m['error'])."\nResolution: ".($m['resolution']??'')."\n";
        }
        return substr($s,0,8000);
    }
    function nm_kb_docs_context(array $chunks): string {
        if(!$chunks) return '';
        $s="PREFER THESE — documented, approved steps:\n";
        foreach($chunks as $c) $s.="\n• ".($c['title']?:$c['book']).": ".substr($c['text'],0,600)."\n";
        return substr($s,0,8000);
    }
}
