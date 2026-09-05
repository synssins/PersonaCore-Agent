"""Audio subsystem: wake word detection, STT, TTS, session management.

Threading patterns (sounddevice):
    Mic side — MicStream wraps sounddevice.InputStream whose C callback runs
    on a dedicated PortAudio thread.  Frames are handed into an asyncio.Queue
    via asyncio.get_running_loop().call_soon_threadsafe; the blocking capture
    loop itself is offloaded with asyncio.to_thread so it never runs on the
    event-loop thread.

    Speaker side — Speaker owns a single daemon threading.Thread
    (``speaker-play``) that blocks on queue.SimpleQueue.get().  PCM chunks are
    pushed onto that queue by enqueue() (thread-safe); the background thread
    drains it and calls sounddevice.OutputStream.write().  There is no
    asyncio.to_thread involved: the thread is created and managed manually so
    it can be kept alive across multiple play requests and torn down cleanly
    on stop().
"""

from workstation_agent.audio.mic import AudioFrame, MicStream
from workstation_agent.audio.ptt import PttConfig, PushToTalk
from workstation_agent.audio.session import AudioEvent, AudioSession, SessionMode
from workstation_agent.audio.sink import Speaker
from workstation_agent.audio.stt import WyomingSTTClient
from workstation_agent.audio.tts import AbortableTask, WyomingTTSClient
from workstation_agent.audio.wake import WakeDetector

__all__ = [
    "AbortableTask",
    "AudioEvent",
    "AudioFrame",
    "AudioSession",
    "MicStream",
    "PttConfig",
    "PushToTalk",
    "SessionMode",
    "Speaker",
    "WakeDetector",
    "WyomingSTTClient",
    "WyomingTTSClient",
]
