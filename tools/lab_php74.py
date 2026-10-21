#!/usr/bin/env python3
"""Reproducible, local Docker lab. No remote target, published port or exploit payload.

Runs bounded allocation failures and benign requests against private disposable Apache workers.
Docker access is required. Does not install a module or change a service on the host.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "85fdda078eaccc94e3c8e7dce64f51d99f4c8dd5"
IMAGE = "php:7.4-apache@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d"


def command(args, timeout=180, check=True, data=None):
    result = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("{} failed: {}".format(args[0], result.stderr.decode(errors="replace")[-2500:]))
    return result


def docker(*args, **kwargs):
    return command(["docker"] + list(args), **kwargs)


def source(variant, directory):
    source_dir = directory / "src"
    source_dir.mkdir(parents=True)
    for name in ["hp_uploadprogress_guard.c", "config.m4", "rfc1867/rfc1867_copy-7.4.c"]:
        target = source_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = command(["git", "-C", ROOT, "show", UPSTREAM + ":src/" + name]).stdout \
            if variant == "upstream" else (ROOT / "src" / name).read_bytes()
        target.write_bytes(data)
    return source_dir


def build(variant, directory, image):
    src = source(variant, directory)
    out = directory / "out"
    out.mkdir()
    script = """set -eu
cp -r /input /tmp/build
cd /tmp/build
phpize > /out/build.log 2>&1
./configure --with-php-config=/usr/local/bin/php-config >> /out/build.log 2>&1
make -j1 >> /out/build.log 2>&1
cp modules/hp_uploadprogress_guard.so /out/module.so
php -n -d extension=/out/module.so --ri hp_uploadprogress_guard > /out/module-info.txt
"""
    docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1",
           "--pids-limit", "128", "--user", "{}:{}".format(os.getuid(), os.getgid()),
           "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=268435456",
           "--mount", "type=bind,source={},target=/input,readonly".format(src),
           "--mount", "type=bind,source={},target=/out".format(out), image, "sh", "-c", script,
           timeout=180)
    return out


def build_observer(directory, image):
    src = directory / "observer"
    src.mkdir()
    shutil.copyfile(str(ROOT / "test/lab/observer.c"), str(src / "observer.c"))
    (src / "config.m4").write_text("PHP_ARG_ENABLE(hp_lab_observer, observer, [--enable-hp-lab-observer], yes)\n"
        "PHP_NEW_EXTENSION(hp_lab_observer, observer.c, $ext_shared)\n")
    docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--memory", "512m", "--pids-limit", "128",
           "--user", "{}:{}".format(os.getuid(), os.getgid()),
           "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=268435456",
           "--mount", "type=bind,source={},target=/input,readonly".format(src),
           "--mount", "type=bind,source={},target=/out".format(directory), image, "sh", "-c",
           "cp -r /input /tmp/build && cd /tmp/build && phpize >/out/observer-build.log 2>&1 "
           "&& ./configure >>/out/observer-build.log 2>&1 && make -j1 >>/out/observer-build.log 2>&1 "
           "&& cp modules/hp_lab_observer.so /out/observer.so", timeout=180)


def cli_case(image, directory, module, code, extra=()):
    name = "hp-upg-cli-" + uuid.uuid4().hex[:10]
    args = ["run", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "256m", "--pids-limit", "64",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=67108864"]
    if module:
        args += ["--mount", "type=bind,source={},target=/lab/module.so,readonly".format(module)]
    args += [image, "php", "-n", "-d", "memory_limit=16M", "-d", "display_errors=0"]
    if module:
        args += ["-d", "extension=/lab/module.so"]
    args += list(extra) + ["-r", code]
    try:
        r = docker(*args, check=False, timeout=15)
        state = json.loads(docker("inspect", "--format", "{{json .State}}", name).stdout)
        return {"exit": state["ExitCode"], "oom_killed_by_container": state["OOMKilled"],
                "stdout": r.stdout.decode(errors="replace"), "stderr": r.stderr.decode(errors="replace")[-1000:]}
    finally:
        docker("rm", "-f", name, check=False)


def multipart(fields, file_data=b"hello\n", progress=False):
    boundary = "hpLabBenignBoundary"
    body = bytearray()
    pairs = list(fields)
    if progress:
        pairs.insert(0, ("PHP_SESSION_UPLOAD_PROGRESS", "lab"))
    for name, value in pairs:
        body.extend(("--" + boundary + '\r\nContent-Disposition: form-data; name="' + name + '"\r\n\r\n').encode())
        body.extend(value.encode() if isinstance(value, str) else value)
        body.extend(b"\r\n")
    if file_data is not None:
        body.extend(("--" + boundary + '\r\nContent-Disposition: form-data; name="sample"; filename="sample.txt"\r\nContent-Type: text/plain\r\n\r\n').encode())
        body.extend(file_data)
        body.extend(b"\r\n")
    body.extend(("--" + boundary + "--\r\n").encode())
    return bytes(body), "multipart/form-data; boundary=" + boundary


def web_cases(variant, directory, module, image, observer, python_runtime=None):
    site = directory / "site"
    site.mkdir()
    for sub in ["", "cap", "mb"]:
        target = site / sub
        target.mkdir(exist_ok=True)
        shutil.copyfile(str(ROOT / "test/lab/probe.php"), str(target / "probe.php"))
    shutil.copyfile(str(ROOT / "tools/runtime-probe.php"), str(site / "private-probe.php"))
    token_file = directory / "probe.token"
    token_file.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
    token_file.chmod(0o644)  # Only in the private, no-network lab; production uses root:www-data 0640.
    manifest_file = directory / "probe-manifest.json"
    manifest_file.write_text(json.dumps({'module_sha256': hashlib.sha256(module.read_bytes()).hexdigest() if module else '0'*64}))
    ini = directory / "lab.ini"
    ini.write_text("memory_limit=32M\npost_max_size=64M\nupload_max_filesize=2M\n"
                   "session.save_path=/tmp\nsession.upload_progress.enabled=1\n"
                   "session.upload_progress.cleanup=0\ndisplay_errors=0\nlog_errors=1\n"
                   "extension=/lab/observer.so\n" + ("extension=/lab/hp_uploadprogress_guard.so\n" if module else ""))
    config = directory / "lab.conf"
    config.write_text("ServerName localhost\nKeepAlive Off\n<IfModule mpm_prefork_module>\n"
                      "StartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nServerLimit 1\n"
                      "MaxRequestWorkers 1\nMaxConnectionsPerChild 0\n</IfModule>\n"
                      '<Directory "/var/www/html/cap">\nphp_admin_value post_max_size 1M\n</Directory>\n'
                      '<Directory "/var/www/html/mb">\nphp_admin_flag mbstring.encoding_translation On\n</Directory>\n')
    name = "hp-upg-web-" + variant + "-" + uuid.uuid4().hex[:8]
    args = ["run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "NET_BIND_SERVICE",
            "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1",
            "--pids-limit", "128", "--tmpfs", "/tmp:rw,nosuid,nodev,size=134217728",
            "--tmpfs", "/var/run/apache2:rw,nosuid,nodev,size=1048576"]
    mounts = [(site, "/var/www/html"), (ini, "/usr/local/etc/php/conf.d/zz-lab.ini"),
              (config, "/etc/apache2/conf-enabled/zz-lab.conf"), (observer, "/lab/observer.so"),
              (token_file, "/etc/php-cve-audit.token"), (manifest_file, "/lab/manifest.json"),
              (ROOT / "tools", "/lab/tools")]
    if python_runtime:
        mounts.append((python_runtime, "/opt/hp-python"))
    if module:
        mounts.append((module, "/lab/hp_uploadprogress_guard.so"))
    for src, target in mounts:
        args += ["--mount", "type=bind,source={},target={},readonly".format(src, target)]
    args += [image]
    docker(*args)

    def request(path="/probe.php", body=None, content_type=None, chunked=False, cookie=None):
        curl = ["exec", "-i", name, "curl", "-sS", "--max-time", "15", "-w", "\nHP_STATUS=%{http_code}"]
        if cookie:
            curl += ["-H", "Cookie: " + cookie]
        curl += ["-H", "Authorization: Basic " + base64.b64encode(b"lab:password").decode()]
        if body is not None:
            curl += ["-H", "Content-Type: " + content_type, "--data-binary", "@-"]
        if chunked:
            curl += ["-H", "Transfer-Encoding: chunked"]
        curl += ["http://127.0.0.1" + path]
        r = docker(*curl, data=body, check=False, timeout=20)
        data, _, status = r.stdout.rpartition(b"\nHP_STATUS=")
        try:
            decoded = json.loads(data)
        except ValueError:
            decoded = None
        return {"curl_exit": r.returncode, "status": int(status or b"0"), "json": decoded,
                "body_tail": data[-100:].decode(errors="replace")}

    try:
        for _ in range(30):
            ready = request()
            if ready["status"] == 200 and ready["json"]:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Apache did not become ready: " + docker("logs", name).stderr.decode())
        results = {"initial": ready}
        results["probe_missing_token"] = request("/private-probe.php?nonce=" + '0'*32)
        if python_runtime and variant == "fork":
            verified = docker("exec", name, "/opt/hp-python/bin/python3", "/lab/tools/check_runtime.py",
                "--url", "http://127.0.0.1/private-probe.php", "--token-file", "/etc/php-cve-audit.token",
                "--manifest", "/lab/manifest.json", check=False)
            results["protected_runtime_checker"] = {'exit': verified.returncode,
                'report': json.loads(verified.stdout), 'stderr': verified.stderr.decode(errors='replace')}
        results["urlencoded"] = request(body=b"hello=world&list%5B%5D=one&list%5B%5D=two", content_type="application/x-www-form-urlencoded")
        body, ct = multipart([("label", "été"), ("nested[item]", "value")])
        results["normal_upload"] = request(body=body, content_type=ct)
        body, ct = multipart([("label", "progress")], progress=True)
        results["progress_upload"] = request(body=body, content_type=ct, cookie="PHPSESSID=hplabprogress")
        results["session_first"] = request(cookie="PHPSESSID=hplabcounter")
        results["session_second"] = request(cookie="PHPSESSID=hplabcounter")
        body, ct = multipart([("label", "multibyte")])
        results["mbstring_native_upload"] = request("/mb/probe.php", body, ct)
        body, ct = multipart([("field" + str(i), "x") for i in range(1100)], file_data=None)
        results["too_many_parts"] = request(body=body, content_type=ct)
        header_body = (b'--hpLabBenignBoundary\r\nContent-Disposition: form-data; name="x"\r\n'
                       b'Content-Type: ' + b'a' * 70000 + b'\r\n\r\ny\r\n--hpLabBenignBoundary--\r\n')
        results["oversized_part_header"] = request(body=header_body,
            content_type="multipart/form-data; boundary=hpLabBenignBoundary")
        results["normal_fatal"] = request("/probe.php?op=fatal")
        results["after_fatal"] = request()
        body, ct = multipart([("large", b"x" * (20 * 1024 * 1024))], file_data=None)
        results["large_field"] = request(body=body, content_type=ct)
        results["after_large_field"] = request()
        body, ct = multipart([("large", b"x" * (2 * 1024 * 1024))], file_data=None)
        results["chunked_over_post_limit"] = request("/cap/probe.php", body, ct, chunked=True)
        results["declared_over_post_limit"] = request("/cap/probe.php", body, ct)
        results["after_chunked"] = request()
        results["application_oom"] = request("/probe.php?op=oom")
        for _ in range(30):
            recovered = request()
            if recovered["status"] == 200 and recovered["json"]:
                break
            time.sleep(0.2)
        results["after_application_oom"] = recovered
        logs = docker("logs", name)
        (directory / "apache.log").write_bytes(logs.stdout + logs.stderr)
        text = (logs.stdout + logs.stderr).decode(errors="replace")
        results["sapi_callback_observation"] = {"safe": text.count("HP_LAB_SAPI_SAFE=1"),
                                                "stale": text.count("HP_LAB_SAPI_SAFE=0")}
        return results
    finally:
        docker("rm", "-f", name, check=False)


def evaluate(report):
    failures = []
    checks = []
    def verify(name, condition):
        checks.append({"name": name, "pass": bool(condition)})
        if not condition:
            failures.append(name)
    for variant, r in report["web"].items():
        for key in ["initial", "urlencoded", "normal_upload", "progress_upload", "session_first",
                    "session_second", "mbstring_native_upload", "after_fatal", "after_large_field",
                    "after_chunked", "after_application_oom"]:
            verify(variant + ":" + key + ":healthy", r[key]["status"] == 200 and r[key]["json"] is not None)
        verify(variant + ":correct_sapi", r["initial"]["json"]["sapi"] == "apache2handler")
        verify(variant + ":probe_refuses_missing_token", r["probe_missing_token"]["status"] == 404)
        verify(variant + ":session_persists", r["session_second"]["json"]["session_requests"] == 2)
        verify(variant + ":upload_digest", r["normal_upload"]["json"]["files"]["sample"]["sha256"] == hashlib.sha256(b"hello\n").hexdigest())
        verify(variant + ":ordinary_fatal_keeps_shutdown", "NORMAL_FATAL_SHUTDOWN" in r["normal_fatal"]["body_tail"])
        if variant != "baseline":
            verify(variant + ":progress_disabled", r["progress_upload"]["json"]["progress_ini"] == "0" and not r["progress_upload"]["json"]["progress_present"])
            verify(variant + ":large_field_dropped", r["large_field"]["status"] == 413 and not r["large_field"]["json"]["post"])
    fork = report["web"]["fork"]
    status = fork["initial"]["json"]["guard_status"]
    for key in ["mitigation_only", "multipart_handler_active", "allocation_error_callback_active",
                "sapi_deactivate_wrapper_active", "upload_progress_callback_absent"]:
        verify("fork:live_status:" + key, status[key])
    verify("fork:unpatched_engine_not_labelled_patched", not status["engine_fix_marker_detected"])
    if "protected_runtime_checker" in fork:
        verify("fork:protected_runtime_checker", fork["protected_runtime_checker"]["exit"] == 0
               and fork["protected_runtime_checker"]["report"]["verdict"] == 'MITIGATION_OBSERVEE_CORRECTIF_MOTEUR_NON_ATTESTE')
    verify("fork:chunked_oversize_dropped", fork["chunked_over_post_limit"]["status"] == 413 and not fork["chunked_over_post_limit"]["json"]["post"])
    verify("fork:oom_worker_replaced", fork["after_application_oom"]["json"]["pid"] != fork["after_chunked"]["json"]["pid"])
    verify("fork:oom_skips_shutdown", "SHUTDOWN_CALLED" not in fork["application_oom"]["body_tail"])
    verify("fork:sapi_pointers_cleared_before_callback", fork["sapi_callback_observation"]["safe"] > 0 and fork["sapi_callback_observation"]["stale"] == 0)
    for key in ["too_many_parts", "oversized_part_header", "declared_over_post_limit"]:
        verify("fork:" + key + ":rejects_partial_input", fork[key]["status"] == 413 and not fork[key]["json"]["post"])
    verify("fork:invalid_mode_stops_startup", report["invalid_mode"]["exit"] != 0
           and "MUST_NOT_RUN" not in report["invalid_mode"]["stdout"])
    for variant, cases in report["cli"].items():
        for name, r in cases.items():
            verify(variant + ":" + name + ":not_container_oom", not r["oom_killed_by_container"])
            if name in ("ordinary_fatal", "fatal_text_contains_oom", "user_fatal", "ordinary_timeout"):
                verify(variant + ":" + name + ":normal_shutdown", r["exit"] == 255 and "SHUTDOWN_CALLED" in r["stdout"])
            elif variant == "fork":
                verify("fork:" + name + ":hard_exit", r["exit"] == 137 and "SHUTDOWN_CALLED" not in r["stdout"])
    report["checks"] = checks
    report["failures"] = failures
    return not failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New private directory for binaries and reports")
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--python-runtime", help="Optional portable Python prefix for checker integration tests")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True)
    image_info = json.loads(docker("image", "inspect", args.image).stdout)[0]
    report = {"upstream_commit": UPSTREAM, "image": args.image, "image_id": image_info["Id"],
              "remote_exploit_executed": False, "cli": {}, "web": {}, "module_sha256": {},
              "lab_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    modules = {}
    for variant in ["upstream", "fork"]:
        directory = output / variant
        directory.mkdir()
        print("Building " + variant, flush=True)
        modules[variant] = build(variant, directory, args.image) / "module.so"
        report["module_sha256"][variant] = hashlib.sha256(modules[variant].read_bytes()).hexdigest()
        if variant == "fork":
            report["fork_source_sha256"] = {str(p.relative_to(directory / "src")): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (directory / "src").rglob('*') if p.is_file()}
    build_observer(output, args.image)
    shutdown = "register_shutdown_function(function(){echo 'SHUTDOWN_CALLED';});"
    cases = {"application_oom": shutdown + "str_repeat('x',33554432);",
             "allocation_overflow": shutdown + "str_repeat('ab',PHP_INT_MAX);",
             "exception_context_oom": shutdown + "try{throw new Exception('test');}finally{str_repeat('x',33554432);}",
             "ordinary_fatal": shutdown + "undefined_lab_function();",
             "fatal_text_contains_oom": shutdown + "$f='Out of memory';$f();",
             "user_fatal": shutdown + "trigger_error('Out of memory: user diagnostic',E_USER_ERROR);"}
    cases["ordinary_timeout"] = shutdown + "while(true){}"
    for variant in ["baseline", "upstream", "fork"]:
        print("Testing " + variant, flush=True)
        module = modules.get(variant)
        directory = output / variant
        directory.mkdir(exist_ok=True)
        report["cli"][variant] = {key: cli_case(args.image, directory, module, code,
            ["-d", "max_execution_time=1"] if key == "ordinary_timeout" else ())
            for key, code in cases.items()}
        report["web"][variant] = web_cases(variant, directory, module, args.image, output / "observer.so",
            Path(args.python_runtime).resolve() if args.python_runtime else None)
    report["invalid_mode"] = cli_case(args.image, output, modules["fork"], "echo 'MUST_NOT_RUN';",
        ["-d", "hp_uploadprogress_guard.mode=typo"])
    passed = evaluate(report)
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"checks": len(report["checks"]), "failures": report["failures"],
                      "report": str(output / "report.json")}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
