from aiogram.fsm.state import State, StatesGroup


class ScanStates(StatesGroup):
    waiting_url = State()
    waiting_nuclei_profile = State()
    waiting_repo = State()
    waiting_archive = State()
    waiting_docker = State()
