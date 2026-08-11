1.   [说明] vLLM 仅支持 Linux/WSL2，当前平台已隐藏该选项
     [1] Ollama       —— 一键启动（兼容性最好，CPU/GPU 皆可）  ← 当前
     [2] Transformers —— 进程内 NF4 基座 + FP16 LoRA（需 8GB+ 显存，精度最高）
     [3] LlamaCPP     —— 实验性，Q4 GGUF + 运行时 LoRA（需适配 CMAKE）
   ------------------------------------------------------------
   请选择推理后端（回车=使用 Ollama，1-3=切换）: 3
   [启动器] 推理后端: llamacpp
   [依赖安装] 后端: llamacpp | 系统: windows/amd64 | GPU: nvidia
   [依赖安装] 检测: llama-cpp-python 0.3.34 (CUDA 预编译 cu125) -> llama-cpp-python 未安装
   [依赖安装] 检测: llama-cpp-python 0.3.34 (CUDA 预编译 cu125) -> llama-cpp-python 未安装
   [依赖安装] 正在安装: llama-cpp-python 0.3.34 (CUDA 预编译 cu125)...
   [依赖安装] 命令: D:\miniconda\python.exe -m pip install --upgrade --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu125 llama-cpp-python==0.3.34 --timeout 60 --retries 5 --progress-bar raw
     Looking in indexes: https://pypi.org/simple, https://abetlen.github.io/llama-cpp-python/whl/cu125
     WARNING: Retrying (Retry(total=4, connect=None, read=None, redirect=None, status=None)) after connection broken by 'ProtocolError('Connection aborted.', ConnectionResetError(10054, 'Զ������ǿ�ȹر���һ�����е����ӡ�', None, 10054, None))': /llama-cpp-python/whl/cu125/llama-cpp-python/
     Collecting llama-cpp-python==0.3.34
     Downloading https://github.com/abetlen/llama-cpp-python/releases/download/v0.3.34-cu125/llama_cpp_python-0.3.34-py3-none-win_amd64.whl (536.7 MB)
     Progress 0 of 536651329
     Progress 262144 of 536651329
     Progress 524288 of 536651329
     Progress 786432 of 536651329
     Progress 1048576 of 536651329
     Progress 1310720 of 536651329
     Progress 1572864 of 536651329
     Progress 1835008 of 536651329
     Progress 2097152 of 536651329
     Progress 2359296 of 536651329
     Progress 2621440 of 536651329
     Progress 2883584 of 536651329
     Progress 3145728 of 536651329
     Progress 3407872 of 536651329
     Progress 3670016 of 536651329
     Progress 3932160 of 536651329
     Progress 4194304 of 536651329
     Progress 4456448 of 536651329
     Progress 4718592 of 536651329
     Progress 4980736 of 536651329
     Progress 5242880 of 536651329
     Progress 5505024 of 536651329
     Progress 5767168 of 536651329
     Progress 6029312 of 536651329
     Progress 6291456 of 536651329
     Progress 6553600 of 536651329
     Progress 6815744 of 536651329
     Progress 7077888 of 536651329
     Progress 7340032 of 536651329
     Progress 7602176 of 536651329
     Progress 7864320 of 536651329
     Progress 8126464 of 536651329
     Progress 8388608 of 536651329
     Progress 8650752 of 536651329
     Progress 8912896 of 536651329
     Progress 9175040 of 536651329
     Progress 9437184 of 536651329
     Progress 9699328 of 536651329
     Progress 9961472 of 536651329
     Progress 10223616 of 536651329
     Progress 10485760 of 536651329
     Progress 10747904 of 536651329
     Progress 11010048 of 536651329
     Progress 11272192 of 536651329
     Progress 11534336 of 536651329
     Progress 11796480 of 536651329
     Progress 12058624 of 536651329
     Progress 12320768 of 536651329
     Progress 12582912 of 536651329
     Progress 12845056 of 536651329
     Progress 13107200 of 536651329
     Progress 13369344 of 536651329
     Progress 13631488 of 536651329
     Progress 13893632 of 536651329
     Progress 14155776 of 536651329
     Progress 14417920 of 536651329
     Progress 14680064 of 536651329
     Progress 14942208 of 536651329
     Progress 15204352 of 536651329
     Progress 15466496 of 536651329
     Progress 15728640 of 536651329
     Progress 15990784 of 536651329
     Progress 16252928 of 536651329
     Progress 16515072 of 536651329
     Progress 16777216 of 536651329
     Progress 17039360 of 536651329
     Progress 17301504 of 536651329
     Progress 17563648 of 536651329
     Progress 17825792 of 536651329
     Progress 18087936 of 536651329
     Progress 18350080 of 536651329
     Progress 18612224 of 536651329
     Progress 18874368 of 536651329
     Progress 19136512 of 536651329
     Progress 19398656 of 536651329
     Progress 19660800 of 536651329
     Progress 19922944 of 536651329
     Progress 20185088 of 536651329
     Progress 20447232 of 536651329
     Progress 20709376 of 536651329
     Progress 20971520 of 536651329
     Progress 21233664 of 536651329
     Progress 21495808 of 536651329
     Progress 21757952 of 536651329
     Progress 22020096 of 536651329
     Progress 22282240 of 536651329
     Progress 22544384 of 536651329
     Progress 22806528 of 536651329
     Progress 23068672 of 536651329
     Progress 23330816 of 536651329
     Progress 23592960 of 536651329
     Progress 23855104 of 536651329
     Progress 24117248 of 536651329
     Progress 24379392 of 536651329
     Progress 24641536 of 536651329
     Progress 24903680 of 536651329
     Progress 25165824 of 536651329
     Progress 25427968 of 536651329
     Progress 25690112 of 536651329
     Progress 25952256 of 536651329
     Progress 26214400 of 536651329
     Progress 26476544 of 536651329
     Progress 26738688 of 536651329
     Progress 27000832 of 536651329
     Progress 27262976 of 536651329
     Progress 27525120 of 536651329
     Progress 27787264 of 536651329
     Progress 28049408 of 536651329
     Progress 28311552 of 536651329
     Progress 28573696 of 536651329
     Progress 28835840 of 536651329
     Progress 29097984 of 536651329
     Progress 29360128 of 536651329
     Progress 29622272 of 536651329
     Progress 29884416 of 536651329
     Progress 30146560 of 536651329
     Progress 30408704 of 536651329
     Progress 30670848 of 536651329
     Progress 30932992 of 536651329
     Progress 31195136 of 536651329
     Progress 31457280 of 536651329
     Progress 31719424 of 536651329
     Progress 31981568 of 536651329
     Progress 32243712 of 536651329
     Progress 32505856 of 536651329
     Progress 32768000 of 536651329
     Progress 33030144 of 536651329
     Progress 33292288 of 536651329
     Progress 33554432 of 536651329
     Progress 33816576 of 536651329
     Progress 34078720 of 536651329
     Progress 34340864 of 536651329
     Progress 34603008 of 536651329
     Progress 34865152 of 536651329
     Progress 35127296 of 536651329
     Progress 35389440 of 536651329
     Progress 35651584 of 536651329
     Progress 35913728 of 536651329
     Progress 36175872 of 536651329
     Progress 36438016 of 536651329
     Progress 36700160 of 536651329
     Progress 36962304 of 536651329
     Progress 37224448 of 536651329
     Progress 37486592 of 536651329
     Progress 37748736 of 536651329
     Progress 38010880 of 536651329
     Progress 38273024 of 536651329
     Progress 38535168 of 536651329
     Progress 38797312 of 536651329
     Progress 39059456 of 536651329
     Progress 39321600 of 536651329
     Progress 39583744 of 536651329
     Progress 39845888 of 536651329
     Progress 40108032 of 536651329
     Progress 40370176 of 536651329
     Progress 40632320 of 536651329
     Progress 40894464 of 536651329
     Progress 41156608 of 536651329
     Progress 41418752 of 536651329
     Progress 41680896 of 536651329
     Progress 41943040 of 536651329
     Progress 42205184 of 536651329
     Progress 42467328 of 536651329
     Progress 42729472 of 536651329
     Progress 42991616 of 536651329
     Progress 43253760 of 536651329
     Progress 43515904 of 536651329
     Progress 43778048 of 536651329
     Progress 44040192 of 536651329
     Progress 44302336 of 536651329
     Progress 44564480 of 536651329
     Progress 44826624 of 536651329
     Progress 45088768 of 536651329
     Progress 45350912 of 536651329
     Progress 45613056 of 536651329
     Progress 45875200 of 536651329
     Progress 46137344 of 536651329
     Progress 46399488 of 536651329
     Progress 46661632 of 536651329
     Progress 46923776 of 536651329
     Progress 47185920 of 536651329
     Progress 47448064 of 536651329
     Progress 47710208 of 536651329
     Progress 47972352 of 536651329
     Progress 48234496 of 536651329
     Progress 48496640 of 536651329
     Progress 48758784 of 536651329
     Progress 49020928 of 536651329
     Progress 49283072 of 536651329
     Progress 49545216 of 536651329
     Progress 49807360 of 536651329
     Progress 50069504 of 536651329
     Progress 50331648 of 536651329
     Progress 50593792 of 536651329
     Progress 50855936 of 536651329
     Progress 51118080 of 536651329
     Progress 51380224 of 536651329
     Progress 51642368 of 536651329
     Progress 51904512 of 536651329
     Progress 52166656 of 536651329
     Progress 52428800 of 536651329
     Progress 52690944 of 536651329
     Progress 52953088 of 536651329
     Progress 53215232 of 536651329
     Progress 53477376 of 536651329
     Progress 53739520 of 536651329
     Progress 54001664 of 536651329
     Progress 54263808 of 536651329
     Progress 54525952 of 536651329
     Progress 54788096 of 536651329
     Progress 55050240 of 536651329
     Progress 55312384 of 536651329
     Progress 55574528 of 536651329
     Progress 55836672 of 536651329
     Progress 56098816 of 536651329
     Progress 56360960 of 536651329
     Progress 56623104 of 536651329
     Progress 56885248 of 536651329
     Progress 57147392 of 536651329
     Progress 57409536 of 536651329
     Progress 57671680 of 536651329
     Progress 57933824 of 536651329
     Progress 58195968 of 536651329
     Progress 58458112 of 536651329
     Progress 58720256 of 536651329
     Progress 58982400 of 536651329
     Progress 59244544 of 536651329
     Progress 59506688 of 536651329
     Progress 59768832 of 536651329
     Progress 60030976 of 536651329
     Progress 60293120 of 536651329
     Progress 60555264 of 536651329
     Progress 60817408 of 536651329
     Progress 61079552 of 536651329
     Progress 61341696 of 536651329
     Progress 61603840 of 536651329
     Progress 61865984 of 536651329
     Progress 62128128 of 536651329
     Progress 62390272 of 536651329
     Progress 62652416 of 536651329
     Progress 62914560 of 536651329
     Progress 63176704 of 536651329
     Progress 63438848 of 536651329
     Progress 63700992 of 536651329
     Progress 63963136 of 536651329
     Progress 64225280 of 536651329
     Progress 64487424 of 536651329
     Progress 64749568 of 536651329
     Progress 65011712 of 536651329
     Progress 65273856 of 536651329
     Progress 65536000 of 536651329
     Progress 65798144 of 536651329
     Progress 66060288 of 536651329
     Progress 66322432 of 536651329
     Progress 66584576 of 536651329
     Progress 66846720 of 536651329
     Progress 67108864 of 536651329
     Progress 67371008 of 536651329
     Progress 67633152 of 536651329
     Progress 67895296 of 536651329
     Progress 68157440 of 536651329
     Progress 68419584 of 536651329
     Progress 68681728 of 536651329
     Progress 68943872 of 536651329
     Progress 69206016 of 536651329
     Progress 69468160 of 536651329
     Progress 69730304 of 536651329
     Progress 69992448 of 536651329
     Progress 70254592 of 536651329
     Progress 70516736 of 536651329
     Progress 70778880 of 536651329
     Progress 71041024 of 536651329
     Progress 71303168 of 536651329
     Progress 71565312 of 536651329
     Progress 71827456 of 536651329
     Progress 72089600 of 536651329
     Progress 72351744 of 536651329
     Progress 72613888 of 536651329
     Progress 72876032 of 536651329
     Progress 73138176 of 536651329
     Progress 73400320 of 536651329
     Progress 73662464 of 536651329
     Progress 73924608 of 536651329
     Progress 74186752 of 536651329
     Progress 74448896 of 536651329
     Progress 74711040 of 536651329
     Progress 74973184 of 536651329
     Progress 75235328 of 536651329
     Progress 75497472 of 536651329
     Progress 75759616 of 536651329
     Progress 76021760 of 536651329
     Progress 76283904 of 536651329
     Progress 76546048 of 536651329
     Progress 76808192 of 536651329
     Progress 77070336 of 536651329
     Progress 77332480 of 536651329
     Progress 77594624 of 536651329
     Progress 77856768 of 536651329
     Progress 78118912 of 536651329
     Progress 78381056 of 536651329
     Progress 78643200 of 536651329
     Progress 78905344 of 536651329
     Progress 79167488 of 536651329
     Progress 79429632 of 536651329
     Progress 79691776 of 536651329
     Progress 79953920 of 536651329
     Progress 80216064 of 536651329
     Progress 80478208 of 536651329
     Progress 80740352 of 536651329
     Progress 81002496 of 536651329
     Progress 81264640 of 536651329
     Progress 81526784 of 536651329
     Progress 81788928 of 536651329
     Progress 82051072 of 536651329
     Progress 82313216 of 536651329
     Progress 82575360 of 536651329
     Progress 82837504 of 536651329
     Progress 83099648 of 536651329
     Progress 83361792 of 536651329
     Progress 83623936 of 536651329
     Progress 83886080 of 536651329
     Progress 84148224 of 536651329
     Progress 84410368 of 536651329
     Progress 84672512 of 536651329
     Progress 84934656 of 536651329
     Progress 85196800 of 536651329
     Progress 85458944 of 536651329
     Progress 85721088 of 536651329
     Progress 85983232 of 536651329
     Progress 86245376 of 536651329
     Progress 86507520 of 536651329
     Progress 86769664 of 536651329
     Progress 87031808 of 536651329
     Progress 87293952 of 536651329
     Progress 87556096 of 536651329
     Progress 87818240 of 536651329
     Progress 88080384 of 536651329
     Progress 88342528 of 536651329
     Progress 88604672 of 536651329
     Progress 88866816 of 536651329
     Progress 89128960 of 536651329
     Progress 89391104 of 536651329
     Progress 89653248 of 536651329
     Progress 89915392 of 536651329
     Progress 90177536 of 536651329
     Progress 90439680 of 536651329
     Progress 90701824 of 536651329
     Progress 90963968 of 536651329
     Progress 91226112 of 536651329
     Progress 91488256 of 536651329
     Progress 91750400 of 536651329
     Progress 92012544 of 536651329
     Progress 92274688 of 536651329
     Progress 92536832 of 536651329
     Progress 92798976 of 536651329
     Progress 93061120 of 536651329
     Progress 93323264 of 536651329
     Progress 93585408 of 536651329
     Progress 93847552 of 536651329
     Progress 94109696 of 536651329
     Progress 94371840 of 536651329
     Progress 94633984 of 536651329
     Progress 94896128 of 536651329
     Progress 95158272 of 536651329
     Progress 95420416 of 536651329
     Progress 95682560 of 536651329
     Progress 95944704 of 536651329
     Progress 96206848 of 536651329
     Progress 96468992 of 536651329
     Progress 96731136 of 536651329
     Progress 96993280 of 536651329
     Progress 97255424 of 536651329
     Progress 97517568 of 536651329
     Progress 97779712 of 536651329
     Progress 98041856 of 536651329
     Progress 98304000 of 536651329
     Progress 98566144 of 536651329
     Progress 98828288 of 536651329
     Progress 99090432 of 536651329
     Progress 99352576 of 536651329
     Progress 99614720 of 536651329
     Progress 99876864 of 536651329
     Progress 100139008 of 536651329
     Progress 100401152 of 536651329
     Progress 100663296 of 536651329
     Progress 100925440 of 536651329
     Progress 101187584 of 536651329
     Progress 101449728 of 536651329
     Progress 101711872 of 536651329
     Progress 101974016 of 536651329
     Progress 102236160 of 536651329
     Progress 102498304 of 536651329
     Progress 102760448 of 536651329
     Progress 103022592 of 536651329
     Progress 103284736 of 536651329
     Progress 103546880 of 536651329
     Progress 103809024 of 536651329
     Progress 104071168 of 536651329
     Progress 104333312 of 536651329
     Progress 104595456 of 536651329
     Progress 104857600 of 536651329
     Progress 105119744 of 536651329
     Progress 105381888 of 536651329
     Progress 105644032 of 536651329
     Progress 105906176 of 536651329
     Progress 106168320 of 536651329
     Progress 106430464 of 536651329
     Progress 106692608 of 536651329
     Progress 106954752 of 536651329
     Progress 107216896 of 536651329
     Progress 107479040 of 536651329
     Progress 107741184 of 536651329
     Progress 108003328 of 536651329
     Progress 108265472 of 536651329
     Progress 108527616 of 536651329
     Progress 108789760 of 536651329
     Progress 109051904 of 536651329
     Progress 109314048 of 536651329
     Progress 109576192 of 536651329
     Progress 109838336 of 536651329
     Progress 110100480 of 536651329
     Progress 110362624 of 536651329
     Progress 110624768 of 536651329
     Progress 110886912 of 536651329
     Progress 111149056 of 536651329
     Progress 111411200 of 536651329
     Progress 111673344 of 536651329
     Progress 111935488 of 536651329
     Progress 112197632 of 536651329
     Progress 112459776 of 536651329
     Progress 112721920 of 536651329
     Progress 112984064 of 536651329
     Progress 113246208 of 536651329
     Progress 113508352 of 536651329
     Progress 113770496 of 536651329
     Progress 114032640 of 536651329
     Progress 114294784 of 536651329
     Progress 114556928 of 536651329
     Progress 114819072 of 536651329
     Progress 115081216 of 536651329
     Progress 115343360 of 536651329
     Progress 115605504 of 536651329
     Progress 115867648 of 536651329
     Progress 116129792 of 536651329
     Progress 116391936 of 536651329
     Progress 116654080 of 536651329
     Progress 116916224 of 536651329
     Progress 117178368 of 536651329
     Progress 117440512 of 536651329
     Progress 117702656 of 536651329
     Progress 117964800 of 536651329
     Progress 118226944 of 536651329
     Progress 118489088 of 536651329
     Progress 118751232 of 536651329
     Progress 119013376 of 536651329
     Progress 119275520 of 536651329
     Progress 119537664 of 536651329
     Progress 119799808 of 536651329
     Progress 120061952 of 536651329
     Progress 120324096 of 536651329
     Progress 120586240 of 536651329
     Progress 120848384 of 536651329
     Progress 121110528 of 536651329
     Progress 121372672 of 536651329
     Progress 121634816 of 536651329
     ERROR: Exception:
     Traceback (most recent call last):
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 438, in _error_catcher
     yield
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 561, in read
     data = self._fp_read(amt) if not fp_closed else b""
     ~~~~~~~~~~~~~^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 527, in _fp_read
     return self._fp.read(amt) if amt is not None else self._fp.read()
     ~~~~~~~~~~~~~^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\cachecontrol\filewrapper.py", line 98, in read
     data: bytes = self.__fp.read(amt)
     ~~~~~~~~~~~~~~^^^^^
     File "D:\miniconda\Lib\http\client.py", line 484, in read
     s = self.fp.read(amt)
     File "D:\miniconda\Lib\socket.py", line 719, in readinto
     return self._sock.recv_into(b)
     ~~~~~~~~~~~~~~~~~~~~^^^
     File "D:\miniconda\Lib\ssl.py", line 1304, in recv_into
     return self.read(nbytes, buffer)
     ~~~~~~~~~^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\ssl.py", line 1138, in read
     return self._sslobj.read(len, buffer)
     ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^
     ConnectionResetError: [WinError 10054] Զ������ǿ�ȹر���һ�����е����ӡ�
     During handling of the above exception, another exception occurred:
     Traceback (most recent call last):
     File "D:\miniconda\Lib\site-packages\pip\_internal\cli\base_command.py", line 107, in _run_wrapper
     status = _inner_run()
     File "D:\miniconda\Lib\site-packages\pip\_internal\cli\base_command.py", line 98, in _inner_run
     return self.run(options, args)
     ~~~~~~~~^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\cli\req_command.py", line 85, in wrapper
     return func(self, options, args)
     File "D:\miniconda\Lib\site-packages\pip\_internal\commands\install.py", line 388, in run
     requirement_set = resolver.resolve(
     reqs, check_supported_wheels=not options.target_dir
     )
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\resolver.py", line 99, in resolve
     result = self._result = resolver.resolve(
     ~~~~~~~~~~~~~~~~^
     collected.requirements, max_rounds=limit_how_complex_resolution_can_be
     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     )
     ^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\resolvelib\resolvers\resolution.py", line 601, in resolve
     state = resolution.resolve(requirements, max_rounds=max_rounds)
     File "D:\miniconda\Lib\site-packages\pip\_vendor\resolvelib\resolvers\resolution.py", line 434, in resolve
     self._add_to_criteria(self.state.criteria, r, parent=None)
     ~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\resolvelib\resolvers\resolution.py", line 150, in _add_to_criteria
     if not criterion.candidates:
     ^^^^^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\resolvelib\structs.py", line 194, in __bool__
     return bool(self._sequence)
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 165, in __bool__
     self._bool = any(self)
     ~~~^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 149, in <genexpr>
     return (c for c in iterator if id(c) not in self._incompatible_ids)
     ^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\found_candidates.py", line 39, in _iter_built
     candidate = func()
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\factory.py", line 180, in _make_candidate_from_link
     base: BaseCandidate | None = self._make_base_candidate_from_link(
     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
     link, template, name, version
     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     )
     ^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\factory.py", line 226, in _make_base_candidate_from_link
     self._link_candidate_cache[link] = LinkCandidate(
     ~~~~~~~~~~~~~^
     link,
     ^^^^^
     ...<3 lines>...
     version=version,
     ^^^^^^^^^^^^^^^^
     )
     ^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 318, in __init__
     super().__init__(
     ~~~~~~~~~~~~~~~~^
     link=link,
     ^^^^^^^^^^
     ...<4 lines>...
     version=version,
     ^^^^^^^^^^^^^^^^
     )
     ^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 161, in __init__
     self.dist = self._prepare()
     ~~~~~~~~~~~~~^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 238, in _prepare
     dist = self._prepare_distribution()
     File "D:\miniconda\Lib\site-packages\pip\_internal\resolution\resolvelib\candidates.py", line 329, in _prepare_distribution
     return preparer.prepare_linked_requirement(self._ireq, parallel_builds=True)
     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\operations\prepare.py", line 543, in prepare_linked_requirement
     return self._prepare_linked_requirement(req, parallel_builds)
     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\operations\prepare.py", line 614, in _prepare_linked_requirement
     local_file = unpack_url(
     link,
     ...<4 lines>...
     hashes,
     )
     File "D:\miniconda\Lib\site-packages\pip\_internal\operations\prepare.py", line 180, in unpack_url
     file = get_http_url(
     link,
     ...<2 lines>...
     hashes=hashes,
     )
     File "D:\miniconda\Lib\site-packages\pip\_internal\operations\prepare.py", line 121, in get_http_url
     from_path, content_type = download(link, temp_dir.path)
     ~~~~~~~~^^^^^^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\network\download.py", line 195, in __call__
     self._process_response(download, resp)
     ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\network\download.py", line 212, in _process_response
     for chunk in chunks:
     ^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\cli\progress_bars.py", line 110, in _raw_progress_bar
     for chunk in iterable:
     ^^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_internal\network\utils.py", line 65, in response_chunks
     for chunk in response.raw.stream(
     ~~~~~~~~~~~~~~~~~~~^
     chunk_size,
     ^^^^^^^^^^^
     ...<22 lines>...
     decode_content=False,
     ^^^^^^^^^^^^^^^^^^^^^
     ):
     ^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 622, in stream
     data = self.read(amt=amt, decode_content=decode_content)
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 560, in read
     with self._error_catcher():
     ~~~~~~~~~~~~~~~~~~~^^
     File "D:\miniconda\Lib\contextlib.py", line 162, in __exit__
     self.gen.throw(value)
     ~~~~~~~~~~~~~~^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 455, in _error_catcher
     raise ProtocolError("Connection broken: %r" % e, e)
     pip._vendor.urllib3.exceptions.ProtocolError: ("Connection broken: ConnectionResetError(10054, 'Զ������ǿ�ȹر���һ�����е����ӡ�', None, 10054, None)", ConnectionResetError(10054, 'Զ������ǿ�ȹر���һ�����е����ӡ�', None, 10054, None))
   [依赖安装] ❌ llama-cpp-python 0.3.34 (CUDA 预编译 cu125) 安装失败（退出码 2）
   [依赖安装] 日志尾部:
   e "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 622, in stream
       data = self.read(amt=amt, decode_content=decode_content)
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 560, in read
       with self._error_catcher():
            ~~~~~~~~~~~~~~~~~~~^^
     File "D:\miniconda\Lib\contextlib.py", line 162, in __exit__
       self.gen.throw(value)
       ~~~~~~~~~~~~~~^^^^^^^
     File "D:\miniconda\Lib\site-packages\pip\_vendor\urllib3\response.py", line 455, in _error_catcher
       raise ProtocolError("Connection broken: %r" % e, e)
   pip._vendor.urllib3.exceptions.ProtocolError: ("Connection broken: ConnectionResetError(10054, 'Զ������ǿ�ȹر���һ�����е����ӡ�', None, 10054, None)", ConnectionResetError(10054, 'Զ������ǿ�ȹر���һ�����е����ӡ�', None, 10054, None))
   [依赖安装] 部分依赖安装失败，可尝试：
     1. 设置 VULN_SCANNER_AUTO_INSTALL_DEPS=0 后手动安装
     2. 或设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端
   
   [错误] llamacpp 后端依赖未就绪。
   # 手动安装 llamacpp 后端依赖（windows/amd64, GPU=nvidia）
   D:\miniconda\python.exe -m pip install --upgrade --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu125 llama-cpp-python==0.3.34 --timeout 60 --retries 5 --progress-bar raw
   
     或设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端。
   
   按回车键退出...
     ~~~~~~~~~~~~~