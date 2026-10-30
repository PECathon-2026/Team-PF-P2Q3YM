"""Human approval adapters. Prompts never include action values."""
import queue
import threading

class ApprovalGate:
    def approve(self, description: str, timeout: float | None = None) -> bool:
        raise NotImplementedError

    def ask_user(self, prompt: str, timeout: float | None = None) -> str | None:
        return None


class CLIPrompt(ApprovalGate):
    def approve(self, description, timeout=None):
        answers = queue.Queue(maxsize=1)
        def read_answer():
            try: answers.put(input(f"Approve {description}? [y/N] ").strip().casefold())
            except (EOFError, KeyboardInterrupt): answers.put("")
        threading.Thread(target=read_answer, daemon=True).start()
        try: return answers.get(timeout=60 if timeout is None else max(0, timeout)) == "y"
        except queue.Empty: return False

    def ask_user(self, prompt, timeout=None):
        answers=queue.Queue(maxsize=1)
        def read_answer():
            try: answers.put(input(prompt+" "))
            except (EOFError,KeyboardInterrupt): answers.put(None)
        threading.Thread(target=read_answer,daemon=True).start()
        try: return answers.get(timeout=60 if timeout is None else max(0,timeout))
        except queue.Empty: return None


class AutoApprove(ApprovalGate):
    def approve(self, description, timeout=None): return True


class AutoDeny(ApprovalGate):
    def approve(self, description, timeout=None): return False
