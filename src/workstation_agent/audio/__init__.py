"""Audio subsystem: wake word detection, STT, TTS, session management.

Threading pattern (sounddevice):
    Both MicStream and Speaker use asyncio.to_thread to run the blocking
    sounddevice read/write loop off the asyncio event loop. Frames are passed
    through an asyncio.Queue bridged from that thread via
    asyncio.get_running_loop().call_soon_threadsafe so that the C callback
    thread never touches the event loop directly.
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
