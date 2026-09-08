"""
gui_app.py
----------
Tkinter GUI for the INF2005 ACW1 steganographic verification tool.

Two tabs (Image / Audio), each with:
  - Protect  : pick a cover file, a message, LSB depth (1-8), a shared
               secret key -> produces a signed stego file; shows a
               before/after comparison and a capacity check.
  - Verify   : pick a (possibly tampered) stego file, a secret key and a
               public key -> shows the verdict + full payload details.
  - Simulate tamper : flips a few bytes in a stego file, well away from
               the hidden data, to produce a negative test case quickly.

Run:  python src/gui_app.py
"""

from __future__ import annotations

import io
import json
import sys
import wave
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, TOP, X, Y, StringVar, IntVar, Text, Tk, ttk, filedialog, messagebox,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import crypto_utils  # noqa: E402
import image_stego  # noqa: E402
import audio_stego  # noqa: E402

from PIL import Image, ImageTk  # noqa: E402

DEFAULT_PRIVATE_KEY = ROOT / "keys" / "private_key.pem"
DEFAULT_PUBLIC_KEY = ROOT / "keys" / "public_key.pem"
DEFAULT_TEAM_ID = "Px-x"

LEARNING_OBJ_SHORT = (
    "Use digital signatures to verify that a payload or file record was issued by a "
    "legitimate signer and has not been altered."
)
PROJECT_OVERVIEW_LARGE = (
    "This undergraduate project requires student teams to design, implement and demonstrate a "
    "GUI-based LSB Replacement steganography program (window-based or web-based) that protects "
    "and verifies both image and audio cover objects using steganography, hashing and digital "
    "signatures. The project focuses on practical cybersecurity concepts: hiding a verification "
    "payload inside an image and an audio file, signing relevant verification data, extracting "
    "the hidden payload, checking the digital signature, and demonstrating positive and negative "
    "verification cases. Video as a cover object is not required for the main assignment, but "
    "may be attempted as an optional challenge."
)


def ensure_keys_exist():
    if not DEFAULT_PRIVATE_KEY.exists() or not DEFAULT_PUBLIC_KEY.exists():
        crypto_utils.generate_keypair(DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY)


class CoverTab(ttk.Frame):
    """Shared UI/logic for the Image and Audio tabs; subclasses provide the
    format-specific embed/extract/preview/tamper functions."""

    cover_type: str = "override-me"
    file_types: list[tuple[str, str]] = []

    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self.cover_path = StringVar()
        self.stego_path = StringVar()
        self.verify_path = StringVar()
        self.secret_key = StringVar(value="team-shared-secret-demo-key")
        self.lsb_depth = IntVar(value=2)
        self.message_choice = StringVar(value="custom")
        self.custom_message = StringVar(value="Custom confidential note from Team Px-x.")
        self.team_id = StringVar(value=DEFAULT_TEAM_ID)

        self._build_protect_section()
        ttk.Separator(self, orient="horizontal").pack(fill=X, pady=8)
        self._build_verify_section()
        ttk.Separator(self, orient="horizontal").pack(fill=X, pady=8)
        self._build_tamper_section()

    # ---- UI construction -------------------------------------------------
    def _build_protect_section(self):
        box = ttk.LabelFrame(self, text=f"1) Protect a {self.cover_type} file", padding=8)
        box.pack(fill=X)

        row = ttk.Frame(box)
        row.pack(fill=X, pady=2)
        ttk.Button(row, text="Choose cover file...", command=self._choose_cover).pack(side=LEFT)
        ttk.Entry(row, textvariable=self.cover_path, width=60).pack(side=LEFT, padx=6)

        msg_row = ttk.Frame(box)
        msg_row.pack(fill=X, pady=4)
        ttk.Label(msg_row, text="Payload message:").pack(side=LEFT)
        ttk.Radiobutton(msg_row, text="Short (learning objective)", variable=self.message_choice,
                         value="short").pack(side=LEFT, padx=4)
        ttk.Radiobutton(msg_row, text="Large (project overview)", variable=self.message_choice,
                         value="large").pack(side=LEFT, padx=4)
        ttk.Radiobutton(msg_row, text="Custom", variable=self.message_choice,
                         value="custom").pack(side=LEFT, padx=4)

        ttk.Label(box, text="Custom message text:").pack(anchor="w")
        self.custom_text = Text(box, height=3, width=80)
        self.custom_text.insert("1.0", self.custom_message.get())
        self.custom_text.pack(fill=X, pady=2)

        opts_row = ttk.Frame(box)
        opts_row.pack(fill=X, pady=4)
        ttk.Label(opts_row, text="LSBs to use (1-8):").pack(side=LEFT)
        ttk.Spinbox(opts_row, from_=1, to=8, textvariable=self.lsb_depth, width=4).pack(side=LEFT, padx=4)
        ttk.Label(opts_row, text="Shared secret key:").pack(side=LEFT, padx=(16, 0))
        ttk.Entry(opts_row, textvariable=self.secret_key, width=30).pack(side=LEFT, padx=4)
        ttk.Label(opts_row, text="Team ID:").pack(side=LEFT, padx=(16, 0))
        ttk.Entry(opts_row, textvariable=self.team_id, width=10).pack(side=LEFT, padx=4)

        btn_row = ttk.Frame(box)
        btn_row.pack(fill=X, pady=4)
        ttk.Button(btn_row, text="Check capacity", command=self._check_capacity).pack(side=LEFT)
        ttk.Button(btn_row, text="Protect (embed + sign)", command=self._do_protect).pack(side=LEFT, padx=6)

        self.protect_output = Text(box, height=8, width=100)
        self.protect_output.pack(fill=BOTH, expand=True, pady=4)

        self.preview_frame = ttk.Frame(box)
        self.preview_frame.pack(fill=X, pady=4)

    def _build_verify_section(self):
        box = ttk.LabelFrame(self, text=f"2) Verify a {self.cover_type} file", padding=8)
        box.pack(fill=X)

        row = ttk.Frame(box)
        row.pack(fill=X, pady=2)
        ttk.Button(row, text="Choose file to verify...", command=self._choose_verify).pack(side=LEFT)
        ttk.Entry(row, textvariable=self.verify_path, width=60).pack(side=LEFT, padx=6)

        key_row = ttk.Frame(box)
        key_row.pack(fill=X, pady=2)
        ttk.Label(key_row, text="Shared secret key:").pack(side=LEFT)
        ttk.Entry(key_row, textvariable=self.secret_key, width=30).pack(side=LEFT, padx=4)
        ttk.Button(key_row, text="Verify", command=self._do_verify).pack(side=LEFT, padx=10)

        self.verify_output = Text(box, height=10, width=100)
        self.verify_output.pack(fill=BOTH, expand=True, pady=4)

    def _build_tamper_section(self):
        box = ttk.LabelFrame(self, text="3) Simulate tampering (negative test helper)", padding=8)
        box.pack(fill=X)
        row = ttk.Frame(box)
        row.pack(fill=X, pady=2)
        ttk.Button(row, text="Tamper a protected file...", command=self._do_tamper).pack(side=LEFT)
        ttk.Label(row, text="(flips a few bytes far away from the hidden data region)").pack(side=LEFT, padx=8)

    # ---- helpers -----------------------------------------------------
    def _choose_cover(self):
        path = filedialog.askopenfilename(title="Choose cover file", filetypes=self.file_types)
        if path:
            self.cover_path.set(path)

    def _choose_verify(self):
        path = filedialog.askopenfilename(title="Choose file to verify", filetypes=self.file_types)
        if path:
            self.verify_path.set(path)

    def _get_message(self) -> str:
        choice = self.message_choice.get()
        if choice == "short":
            return LEARNING_OBJ_SHORT
        if choice == "large":
            return PROJECT_OVERVIEW_LARGE
        return self.custom_text.get("1.0", END).strip()

    def _log(self, widget: Text, text: str, clear: bool = True):
        if clear:
            widget.delete("1.0", END)
        widget.insert(END, text)

    # ---- actions (implemented via subclass hooks) ---------------------
    def _check_capacity(self):
        path = self.cover_path.get()
        if not path:
            messagebox.showwarning("No file", "Choose a cover file first.")
            return
        try:
            report = self.capacity_report(path, self.lsb_depth.get())
            message = self._get_message()
            msg_bytes = len(message.encode("utf-8"))
            ok = msg_bytes <= report["max_message_bytes"]
            lines = [
                f"Cover capacity report for: {path}",
                json.dumps(report, indent=2),
                "",
                f"Selected message length: {msg_bytes} bytes",
                f"Fits within capacity: {'YES' if ok else 'NO -- payload larger than cover object capacity!'}",
            ]
            self._log(self.protect_output, "\n".join(lines))
        except Exception as exc:
            messagebox.showerror("Capacity check failed", str(exc))

    def _do_protect(self):
        cover = self.cover_path.get()
        if not cover:
            messagebox.showwarning("No file", "Choose a cover file first.")
            return
        ensure_keys_exist()
        try:
            private_key = crypto_utils.load_private_key(DEFAULT_PRIVATE_KEY)
            message = self._get_message()
            secret_key = self.secret_key.get().encode("utf-8")
            lsb = self.lsb_depth.get()
            src = Path(cover)
            out_dir = ROOT / "samples" / "protected"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{src.stem}_stego{src.suffix}"

            stats = self.embed(
                cover, str(out_path), secret_key=secret_key, private_key=private_key,
                message=message, lsb_depth=lsb, media_id=f"{src.stem}-{self.cover_type}",
                team_id=self.team_id.get(),
            )
            self.stego_path.set(str(out_path))
            self.verify_path.set(str(out_path))

            lines = [
                f"Stego file written to: {out_path}",
                f"Start offset (secret, derived from key+salt): {stats['start_offset']}",
                f"LSBs used: {stats['lsb_depth']}   Capsule size: {stats['capsule_len']} bytes",
                f"Capacity used / available: {stats['capacity_bytes_used']} / {stats['capacity_bytes_available']} bytes",
                "",
                "Embedded payload:",
                json.dumps(stats["payload"], indent=2),
            ]
            self._log(self.protect_output, "\n".join(lines))
            self._show_preview(cover, str(out_path))
        except Exception as exc:
            messagebox.showerror("Protect failed", str(exc))

    def _do_verify(self):
        path = self.verify_path.get()
        if not path:
            messagebox.showwarning("No file", "Choose a file to verify first.")
            return
        try:
            public_key = crypto_utils.load_public_key(DEFAULT_PUBLIC_KEY)
            secret_key = self.secret_key.get().encode("utf-8")
            result = self.extract_and_verify(path, secret_key=secret_key, public_key=public_key)
            lines = [
                f"File: {path}",
                f"VERDICT: {result['verdict']}",
                f"Detail: {result['detail']}",
            ]
            if result.get("start_offset") is not None:
                lines.append(f"Recovered start offset: {result['start_offset']}")
            if result.get("payload"):
                lines.append("")
                lines.append("Extracted payload:")
                lines.append(json.dumps(result["payload"], indent=2))
            self._log(self.verify_output, "\n".join(lines))
        except Exception as exc:
            messagebox.showerror("Verify failed", str(exc))

    def _do_tamper(self):
        path = filedialog.askopenfilename(title="Choose a protected file to tamper", filetypes=self.file_types)
        if not path:
            return
        try:
            out_path = self.tamper(path)
            self.verify_path.set(out_path)
            messagebox.showinfo("Tampered file created", f"Wrote tampered copy:\n{out_path}\n\n"
                                                            "Now click Verify to see the negative case.")
        except Exception as exc:
            messagebox.showerror("Tamper failed", str(exc))

    def _show_preview(self, before_path: str, after_path: str):
        for child in self.preview_frame.winfo_children():
            child.destroy()

    # ---- to be overridden ----------------------------------------------
    def capacity_report(self, path, lsb_depth):
        raise NotImplementedError

    def embed(self, *args, **kwargs):
        raise NotImplementedError

    def extract_and_verify(self, *args, **kwargs):
        raise NotImplementedError

    def tamper(self, path: str) -> str:
        raise NotImplementedError


class ImageTab(CoverTab):
    cover_type = "image"
    file_types = [("PNG images", "*.png"), ("All files", "*.*")]

    def capacity_report(self, path, lsb_depth):
        return image_stego.capacity_report(path, lsb_depth)

    def embed(self, *args, **kwargs):
        return image_stego.embed_image(*args, **kwargs)

    def extract_and_verify(self, *args, **kwargs):
        return image_stego.extract_and_verify_image(*args, **kwargs)

    def tamper(self, path: str) -> str:
        img = Image.open(path)
        img.load()
        px = img.load()
        w, h = img.size
        # flip a handful of pixels in the bottom-right corner, far from the
        # header margin/derived payload region for a typical demo file.
        for dx in range(5):
            for dy in range(5):
                x, y = w - 1 - dx, h - 1 - dy
                pixel = px[x, y]
                inverted = tuple(255 - c for c in pixel[:3]) + tuple(pixel[3:])
                px[x, y] = inverted
        out_path = str(Path(path).with_name(Path(path).stem + "_tampered" + Path(path).suffix))
        img.save(out_path)
        return out_path

    def _show_preview(self, before_path: str, after_path: str):
        super()._show_preview(before_path, after_path)
        try:
            for label_text, p in (("Original", before_path), ("Stego", after_path)):
                col = ttk.Frame(self.preview_frame)
                col.pack(side=LEFT, padx=8)
                ttk.Label(col, text=label_text).pack()
                img = Image.open(p)
                img.thumbnail((220, 220))
                photo = ImageTk.PhotoImage(img)
                lbl = ttk.Label(col, image=photo)
                lbl.image = photo  # keep reference
                lbl.pack()
        except Exception:
            pass  # preview is a convenience only


class AudioTab(CoverTab):
    cover_type = "audio"
    file_types = [("WAV audio", "*.wav"), ("All files", "*.*")]

    def capacity_report(self, path, lsb_depth):
        return audio_stego.capacity_report(path, lsb_depth)

    def embed(self, *args, **kwargs):
        return audio_stego.embed_audio(*args, **kwargs)

    def extract_and_verify(self, *args, **kwargs):
        return audio_stego.extract_and_verify_audio(*args, **kwargs)

    def tamper(self, path: str) -> str:
        with wave.open(path, "rb") as wf:
            params = wf.getparams()
            raw = bytearray(wf.readframes(params.nframes))
        # flip bytes in the last 20 bytes of the file, far from the header
        # margin/derived payload region for a typical demo file.
        for i in range(1, 21):
            raw[-i] ^= 0xFF
        out_path = str(Path(path).with_name(Path(path).stem + "_tampered" + Path(path).suffix))
        with wave.open(out_path, "wb") as wf:
            wf.setparams(params)
            wf.writeframes(bytes(raw))
        return out_path

    def _show_preview(self, before_path: str, after_path: str):
        super()._show_preview(before_path, after_path)
        try:
            for label_text, p in (("Original", before_path), ("Stego", after_path)):
                with wave.open(p, "rb") as wf:
                    params = wf.getparams()
                col = ttk.Frame(self.preview_frame)
                col.pack(side=LEFT, padx=8)
                ttk.Label(
                    col,
                    text=f"{label_text}\n{params.nchannels}ch {params.sampwidth*8}-bit "
                         f"{params.framerate}Hz\n{params.nframes/params.framerate:.2f}s",
                ).pack()
                play_btn = ttk.Button(col, text="Play", command=lambda p=p: self._play(p))
                play_btn.pack()
        except Exception:
            pass

    def _play(self, path: str):
        try:
            import winsound
            winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        except Exception as exc:
            messagebox.showinfo("Playback unavailable", f"Could not play audio automatically: {exc}\n"
                                                          f"Open the file manually instead:\n{path}")


def main():
    ensure_keys_exist()
    root = Tk()
    root.title("INF2005 ACW1 - Steganographic Integrity Verification Tool")
    root.geometry("1000x800")

    notebook = ttk.Notebook(root)
    notebook.pack(fill=BOTH, expand=True)

    image_tab = ImageTab(notebook)
    audio_tab = AudioTab(notebook)
    notebook.add(image_tab, text="Image")
    notebook.add(audio_tab, text="Audio")

    root.mainloop()


if __name__ == "__main__":
    main()
