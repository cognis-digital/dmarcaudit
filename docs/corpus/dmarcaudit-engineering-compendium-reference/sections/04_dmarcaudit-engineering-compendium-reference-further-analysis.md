## 4. dmarcaudit — Engineering Compendium & Reference — further analysis 4

### Advanced Spoofability Metrics and Their Implications

(error: slot on :8774 unreachable after 4 tries: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>)

### SPF Record Syntax Variants and Their Impact on Validation

(error: slot on :8774 unreachable after 4 tries: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>)

### DKIM Signature Integrity Across Email Clients and Servers

(error: slot on :8774 unreachable after 4 tries: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>)

### DMARC Policy Enforcement in Mixed-Technology Environments

(error: slot on :8774 unreachable after 4 tries: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>)

### DNSSEC Integration and Its Role in Mitigating Spoofing Risks

(error: [uncensored] llama-server died.
_decoded =    364, tg =   4.56 t/s
1.33.186.364 I slot print_timing: id  3 | task 0 | n_decoded =    378, tg =   4.56 t/s
1.36.370.199 I slot print_timing: id  3 | task 0 | n_decoded =    392, tg =   4.55 t/s
1.39.460.267 I slot print_timing: id  3 | task 0 | n_decoded =    406, tg =   4.55 t/s
1.42.594.303 I slot print_timing: id  3 | task 0 | n_decoded =    420, tg =   4.55 t/s
1.45.612.006 I slot print_timing: id  3 | task 0 | n_decoded =    434, tg =   4.55 t/s
1.48.723.160 I slot print_timing: id  3 | task 0 | n_decoded =    448, tg =   4.55 t/s
1.51.836.188 I slot print_timing: id  3 | task 0 | n_decoded =    462, tg =   4.55 t/s
1.54.975.717 I slot print_timing: id  3 | task 0 | n_decoded =    476, tg =   4.55 t/s

=== start 2026-09-10 05:08:17 ===
cmd: C:\Users\user\Downloads\aeon-everything-cog-feature\tools\llama-vulkan\llama-server.exe -m C:\Users\user\Downloads\aeon-everything-cog-feature\models\Josiefied-Qwen3-8B-abliterated-v1-Q5_K_M.gguf --port 8774 --host 127.0.0.1 --no-webui -a uncensored -ngl 99 -c 16384 --cache-type-k q8_0 --cache-type-v q8_0 --flash-attn on -t 8 --jinja --temp 0.7 --top-k 40 --top-p 0.95 --min-p 0.05 --repeat-penalty 1.05 --repeat-last-n 64
0.00.065.356 I log_info: verbosity = 3 (adjust with the `-lv N` CLI arg)
0.00.065.363 I device_info:
0.00.065.370 I   - CPU     : AMD Ryzen 9 5950X 16-Core Processor             (130996 MiB, 84035 MiB free)
0.00.065.413 I system_info: n_threads = 8 (n_threads_batch = 8) / 32 | CPU : SSE3 = 1 | SSSE3 = 1 | AVX = 1 | AVX2 = 1 | F16C = 1 | FMA = 1 | BMI2 = 1 | LLAMAFILE = 1 | OPENMP = 1 | REPACK = 1 | 
0.00.065.419 I srv  llama_server: n_parallel is set to auto, using n_parallel = 4 and kv_unified = true
0.00.065.457 I srv          init: running without SSL
0.00.065.475 I srv          init: using 31 threads for HTTP server
0.00.065.480 I srv          init: The UI is disabled
0.00.065.480 I srv          init: Use --ui/--no-ui (or deprecated --webui/--no-webui) to enable/disable
0.00.065.594 I srv         start: binding port with default address family
0.00.068.430 I srv  llama_server: loading model
0.00.068.442 I srv    load_model: loading model 'C:\Users\user\Downloads\aeon-everything-cog-feature\models\Josiefied-Qwen3-8B-abliterated-v1-Q5_K_M.gguf'
0.00.068.521 I common_init_result: fitting params to device memory ...
0.00.068.527 I common_init_result: (for bugs during this step try to reproduce them with -fit off, or provide --verbose logs if the bug only occurs with -fit on)
0.00.349.585 I common_params_fit_impl: projected to use 7151 MiB of host memory vs. 130996 MiB of total host memory
0.00.570.761 W load: control-looking token: 128247 '</s>' was not control-type; this is probably a bug in the model. its type will be overridden
0.01.011.596 W llama_context: n_ctx_seq (16384) < n_ctx_train (40960) -- the full capacity of the model will not be utilized
0.01.173.638 I common_init_from_params: warming up the model with an empty run - please wait ... (--no-warmup to disable)
)

### Case Studies: Real-World DMARC Failures and Post-Mortem Analysis

(error: slot on :8774 unreachable after 4 tries: <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>)
