"""
gui_app.py
----------
Tkinter GUI for the INF2005 ACW1 steganographic verification tool.

Layout: a window with two tabs, "Image" and "Audio".  Both tabs share the
same three sections (built once in `CoverTab`); each tab only plugs in the
format-specific embed / verify / preview / tamper functions.

Sections on every tab:
  1) Protect  - choose a cover file, type/pick a message, choose the LSB
                depth (1-8) and the shared secret key, run a capacity check,
                then embed + sign.  Shows the cover BEFORE encoding and a
                cover-vs-stego comparison AFTER encoding.
  2) Verify   - choose a (possibly tampered) stego file + keys, get a
                verdict, the recovered payload, and a preview of the stego
                object plus the recovered hidden message (AFTER decoding).
  3) Simulate tamper - flip a few bytes far from the hidden data to make a
                negative test case in one click.

Run:  python src/gui_app.py
"""

from __future__ import annotations

import json
import sys
import wave
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, X, StringVar, IntVar, Text, Tk, ttk, filedialog, messagebox,
)

# Make `src/` importable whether the script is run from the repo root or from src/.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import crypto_utils  # noqa: E402
import image_stego  # noqa: E402
import audio_stego  # noqa: E402
import payload as payload_mod  # noqa: E402

from PIL import Image, ImageTk  # noqa: E402

DEFAULT_PRIVATE_KEY = ROOT / "keys" / "private_key.pem"
DEFAULT_PUBLIC_KEY = ROOT / "keys" / "public_key.pem"
DEFAULT_TEAM_ID = payload_mod.TEAM_ID_DEFAULT

# The two canned messages the assignment asks for ("various payload sizes"):
# a short one (a Learning Outcome) and a large one (the Project Overview).
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
    """Generate the demo RSA key pair on first run if it is missing."""
    if not DEFAULT_PRIVATE_KEY.exists() or not DEFAULT_PUBLIC_KEY.exists():
        crypto_utils.generate_keypair(DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY)


class CoverTab(ttk.Frame):
    """Shared UI and logic for the Image and Audio tabs.

    Subclasses set `cover_type` / `file_types` and implement the four hooks
    at the bottom (`capacity_report`, `embed`, `extract_and_verify`,
    `tamper`) plus the optional preview hooks.
    """

    cover_type: str = "override-me"
    file_types: list[tuple[str, str]] = []

    def __init__(self, parent):
        super().__init__(parent, padding=10)

        # Keeps PhotoImage objects alive - Tk only holds a weak reference,
        # so without this thumbnails get garbage-collected and go blank.
        self._photo_refs = []

        # --- Tk variables bound to the input widgets ---
        self.cover_path = StringVar()      # cover file chosen in section 1
        self.stego_path = StringVar()      # stego file produced by Protect
        self.verify_path = StringVar()     # file chosen in section 2
        self.secret_key = StringVar(value="team-shared-secret-demo-key")
        self.lsb_depth = IntVar(value=2)
        self.message_choice = StringVar(value="custom")  # short / large / custom
        self.custom_message = StringVar(value=f"Custom confidential note from Team {DEFAULT_TEAM_ID}.")
        self.team_id = StringVar(value=DEFAULT_TEAM_ID)

        # --- Build the three sections, separated by horizontal rules ---
        self._build_protect_section()
        ttk.Separator(self, orient="horizontal").pack(fill=X, pady=8)
        self._build_verify_section()
        ttk.Separator(self, orient="horizontal").pack(fill=X, pady=8)
        self._build_tamper_section()

    # ==== UI construction ==============================================
    def _build_protect_section(self):
        """Section 1: pick a cover, a message, options; capacity check + Protect."""
        box = ttk.LabelFrame(self, text=f"1) Protect a {self.cover_type} file", padding=8)
        box.pack(fill=X)

        # Row: choose cover file.
        row = ttk.Frame(box)
        row.pack(fill=X, pady=2)
        ttk.Button(row, text="Choose cover file...", command=self._choose_cover).pack(side=LEFT)
        ttk.Entry(row, textvariable=self.cover_path, width=60).pack(side=LEFT, padx=6)

        # Row: which message to embed.
        msg_row = ttk.Frame(box)
        msg_row.pack(fill=X, pady=4)
        ttk.Label(msg_row, text="Payload message:").pack(side=LEFT)
        ttk.Radiobutton(msg_row, text="Short (learning objective)", variable=self.message_choice,
                        value="short").pack(side=LEFT, padx=4)
        ttk.Radiobutton(msg_row, text="Large (project overview)", variable=self.message_choice,
                        value="large").pack(side=LEFT, padx=4)
        ttk.Radiobutton(msg_row, text="Custom", variable=self.message_choice,
                        value="custom").pack(side=LEFT, padx=4)

        # Free-text box used when "Custom" is selected.
        ttk.Label(box, text="Custom message text:").pack(anchor="w")
        self.custom_text = Text(box, height=3, width=80)
        self.custom_text.insert("1.0", self.custom_message.get())
        self.custom_text.pack(fill=X, pady=2)

        # Row: LSB depth spinbox (FR: selectable 1-8), secret key, team id.
        opts_row = ttk.Frame(box)
        opts_row.pack(fill=X, pady=4)
        ttk.Label(opts_row, text="LSBs to use (1-8):").pack(side=LEFT)
        ttk.Spinbox(opts_row, from_=1, to=8, textvariable=self.lsb_depth, width=4).pack(side=LEFT, padx=4)
        ttk.Label(opts_row, text="Shared secret key:").pack(side=LEFT, padx=(16, 0))
        ttk.Entry(opts_row, textvariable=self.secret_key, width=30).pack(side=LEFT, padx=4)
        ttk.Label(opts_row, text="Team ID:").pack(side=LEFT, padx=(16, 0))
        ttk.Entry(opts_row, textvariable=self.team_id, width=10).pack(side=LEFT, padx=4)

        # Row: action buttons.
        btn_row = ttk.Frame(box)
        btn_row.pack(fill=X, pady=4)
        ttk.Button(btn_row, text="Check capacity", command=self._check_capacity).pack(side=LEFT)
        ttk.Button(btn_row, text="Protect (embed + sign)", command=self._do_protect).pack(side=LEFT, padx=6)

        # Text log + preview strip for this section.
        self.protect_output = Text(box, height=8, width=100)
        self.protect_output.pack(fill=BOTH, expand=True, pady=4)
        self.preview_frame = ttk.Frame(box)   # holds "before" / "before vs after" thumbnails
        self.preview_frame.pack(fill=X, pady=4)

    def _build_verify_section(self):
        """Section 2: pick a file + secret key, Verify, show verdict + preview."""
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

        # Preview strip for the DECODE side: the stego object + the recovered
        # hidden message (spec: compare/"play" cover and stego after decoding).
        self.verify_preview_frame = ttk.Frame(box)
        self.verify_preview_frame.pack(fill=X, pady=4)

    def _build_tamper_section(self):
        """Section 3: one-click helper to produce a tampered negative case."""
        box = ttk.LabelFrame(self, text="3) Simulate tampering (negative test helper)", padding=8)
        box.pack(fill=X)
        row = ttk.Frame(box)
        row.pack(fill=X, pady=2)
        ttk.Button(row, text="Tamper a protected file...", command=self._do_tamper).pack(side=LEFT)
        ttk.Label(row, text="(flips a few bytes far away from the hidden data region)").pack(side=LEFT, padx=8)

    # ==== Small helpers ================================================
    def _choose_cover(self):
        """File dialog for the cover file; also shows a 'before encoding' preview."""
        path = filedialog.askopenfilename(title="Choose cover file", filetypes=self.file_types)
        if path:
            self.cover_path.set(path)
            self._clear_frame(self.preview_frame)
            self._show_cover_preview(path)  # per-format hook

    def _choose_verify(self):
        path = filedialog.askopenfilename(title="Choose file to verify", filetypes=self.file_types)
        if path:
            self.verify_path.set(path)

    def _get_message(self) -> str:
        """Resolve the selected radio button to the actual message text."""
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

    @staticmethod
    def _clear_frame(frame: ttk.Frame):
        for child in frame.winfo_children():
            child.destroy()

    # ==== Button actions ==============================================
    def _check_capacity(self):
        """Mandatory 'is the payload bigger than the cover?' check."""
        path = self.cover_path.get()
        if not path:
            messagebox.showwarning("No file", "Choose a cover file first.")
            return
        try:
            # team_id is threaded through: a longer id shrinks the message room.
            report = self.capacity_report(path, self.lsb_depth.get(), self.team_id.get())
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
        """Embed + sign: writes a stego file next to the originals and shows
        a cover-vs-stego comparison."""
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
            # Point the Verify section at the file we just made.
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

            # AFTER encoding: show original vs stego for comparison.
            self._clear_frame(self.preview_frame)
            self._show_pair_preview(self.preview_frame, cover, str(out_path),
                                    labels=("Original (before)", "Stego (after encoding)"))
        except Exception as exc:
            messagebox.showerror("Protect failed", str(exc))

    def _do_verify(self):
        """Extract + verify: shows the verdict, the recovered payload, and a
        preview of the stego object plus the recovered hidden message."""
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

            # AFTER decoding: preview the stego object and "play"/show the
            # recovered hidden message.
            self._clear_frame(self.verify_preview_frame)
            self._show_verify_preview(path, result)
        except Exception as exc:
            messagebox.showerror("Verify failed", str(exc))

    def _do_tamper(self):
        """Make a tampered copy of a protected file for a negative test."""
        path = filedialog.askopenfilename(title="Choose a protected file to tamper", filetypes=self.file_types)
        if not path:
            return
        try:
            out_path = self.tamper(path)
            self.verify_path.set(out_path)
            messagebox.showinfo("Tampered file created",
                                f"Wrote tampered copy:\n{out_path}\n\nNow click Verify to see the negative case.")
        except Exception as exc:
            messagebox.showerror("Tamper failed", str(exc))

    # ==== Preview helpers (shared) ====================================
    def _show_recovered_message(self, frame: ttk.Frame, result: dict):
        """Render the recovered hidden message ('play/execute the payload' for
        a text payload) below whatever media preview the subclass drew."""
        payload = result.get("payload") or {}
        msg = payload.get("message")
        box = ttk.LabelFrame(frame, text="Recovered hidden message (payload)", padding=6)
        box.pack(fill=X, pady=4)
        text = Text(box, height=4, width=100, wrap="word")
        text.insert("1.0", msg if msg else "(no payload recovered - see verdict above)")
        text.configure(state="disabled")
        text.pack(fill=X)

    def _show_pair_preview(self, frame: ttk.Frame, left_path: str, right_path: str,
                            labels: "tuple[str, str]"):
        """Default 'two things side by side' preview - subclasses override
        with real thumbnails / audio players."""
        for label_text, p in zip(labels, (left_path, right_path)):
            col = ttk.Frame(frame)
            col.pack(side=LEFT, padx=8)
            ttk.Label(col, text=f"{label_text}\n{Path(p).name}").pack()

    # ==== Hooks for subclasses =======================================
    def capacity_report(self, path, lsb_depth, team_id):
        raise NotImplementedError

    def embed(self, *args, **kwargs):
        raise NotImplementedError

    def extract_and_verify(self, *args, **kwargs):
        raise NotImplementedError

    def tamper(self, path: str) -> str:
        raise NotImplementedError

    def _show_cover_preview(self, path: str):
        """'Before encoding' preview - default no-op."""

    def _show_verify_preview(self, stego_path: str, result: dict):
        """'After decoding' preview - default: just show the recovered message."""
        self._show_recovered_message(self.verify_preview_frame, result)


class ImageTab(CoverTab):
    cover_type = "image"
    file_types = [("PNG images", "*.png"), ("All files", "*.*")]

    def capacity_report(self, path, lsb_depth, team_id):
        return image_stego.capacity_report(path, lsb_depth, team_id)

    def embed(self, *args, **kwargs):
        return image_stego.embed_image(*args, **kwargs)

    def extract_and_verify(self, *args, **kwargs):
        return image_stego.extract_and_verify_image(*args, **kwargs)

    def tamper(self, path: str) -> str:
        """Invert a 5x5 block of pixels in the bottom-right corner - far from
        the header margin and (for a normal demo file) the payload region -
        so the change is caught by the cover hash, not the signature."""
        img = Image.open(path)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        px = img.load()
        assert px is not None
        w, h = img.size
        for dx in range(5):
            for dy in range(5):
                x, y = w - 1 - dx, h - 1 - dy
                pixel = px[x, y]
                assert isinstance(pixel, tuple)
                inverted = tuple(255 - c for c in pixel[:3]) + tuple(pixel[3:])
                px[x, y] = inverted
        out_path = str(Path(path).with_name(Path(path).stem + "_tampered" + Path(path).suffix))
        img.save(out_path)
        return out_path

    # ---- previews ----------------------------------------------------
    def _thumb(self, parent, label_text: str, path: str):
        """One labelled thumbnail column."""
        col = ttk.Frame(parent)
        col.pack(side=LEFT, padx=8)
        ttk.Label(col, text=label_text).pack()
        try:
            img = Image.open(path)
            img.thumbnail((220, 220))
            photo = ImageTk.PhotoImage(img)
            lbl = ttk.Label(col, image=photo)
            self._photo_refs.append(photo)  # keep a reference or Tk garbage-collects it
            lbl.pack()
        except Exception as exc:
            ttk.Label(col, text=f"(preview failed: {exc})").pack()

    def _show_cover_preview(self, path: str):
        self._thumb(self.preview_frame, "Cover (before encoding)", path)

    def _show_pair_preview(self, frame, left_path, right_path, labels: "tuple[str, str]"):
        self._thumb(frame, labels[0], left_path)
        self._thumb(frame, labels[1], right_path)

    def _show_verify_preview(self, stego_path: str, result: dict):
        # Compare the original cover (if still selected) with the stego file...
        cover = self.cover_path.get()
        if cover and Path(cover).exists():
            self._thumb(self.verify_preview_frame, "Original cover", cover)
        self._thumb(self.verify_preview_frame, "Stego (being verified)", stego_path)
        # ...then show the recovered hidden message underneath.
        self._show_recovered_message(self.verify_preview_frame, result)


class AudioTab(CoverTab):
    cover_type = "audio"
    file_types = [("WAV audio", "*.wav"), ("All files", "*.*")]

    def capacity_report(self, path, lsb_depth, team_id):
        return audio_stego.capacity_report(path, lsb_depth, team_id)

    def embed(self, *args, **kwargs):
        return audio_stego.embed_audio(*args, **kwargs)

    def extract_and_verify(self, *args, **kwargs):
        return audio_stego.extract_and_verify_audio(*args, **kwargs)

    def tamper(self, path: str) -> str:
        """Flip the last 20 bytes of frame data - safely past the header and
        (for a normal demo file) the payload region."""
        with wave.open(path, "rb") as wf:
            params = wf.getparams()
            raw = bytearray(wf.readframes(params.nframes))
        for i in range(1, 21):
            raw[-i] ^= 0xFF
        out_path = str(Path(path).with_name(Path(path).stem + "_tampered" + Path(path).suffix))
        with wave.open(out_path, "wb") as wf:
            wf.setparams(params)
            wf.writeframes(bytes(raw))
        return out_path

    # ---- previews ----------------------------------------------------
    def _audio_column(self, parent, label_text: str, path: str):
        """One labelled column: format summary + a Play button."""
        col = ttk.Frame(parent)
        col.pack(side=LEFT, padx=8)
        try:
            with wave.open(path, "rb") as wf:
                p = wf.getparams()
            summary = (f"{label_text}\n{p.nchannels}ch {p.sampwidth * 8}-bit "
                       f"{p.framerate}Hz\n{p.nframes / p.framerate:.2f}s")
        except Exception as exc:
            summary = f"{label_text}\n(info failed: {exc})"
        ttk.Label(col, text=summary).pack()
        ttk.Button(col, text="Play", command=lambda: self._play(path)).pack()

    def _show_cover_preview(self, path: str):
        self._audio_column(self.preview_frame, "Cover (before encoding)", path)

    def _show_pair_preview(self, frame, left_path, right_path, labels: "tuple[str, str]"):
        self._audio_column(frame, labels[0], left_path)
        self._audio_column(frame, labels[1], right_path)

    def _show_verify_preview(self, stego_path: str, result: dict):
        cover = self.cover_path.get()
        if cover and Path(cover).exists():
            self._audio_column(self.verify_preview_frame, "Original cover", cover)
        self._audio_column(self.verify_preview_frame, "Stego (being verified)", stego_path)
        self._show_recovered_message(self.verify_preview_frame, result)

    def _play(self, path: str):
        """Play a WAV via Windows' built-in winsound (async so the UI stays live)."""
        try:
            import winsound
            winsound.PlaySound(path, winsound.SND_FILENAME | winsound.SND_ASYNC)
        except Exception as exc:
            messagebox.showinfo("Playback unavailable",
                                f"Could not play audio automatically: {exc}\n"
                                f"Open the file manually instead:\n{path}")


def main():
    ensure_keys_exist()
    root = Tk()
    root.title("INF2005 ACW1 - Steganographic Integrity Verification Tool")
    root.geometry("1000x800")

    notebook = ttk.Notebook(root)
    notebook.pack(fill=BOTH, expand=True)
    notebook.add(ImageTab(notebook), text="Image")
    notebook.add(AudioTab(notebook), text="Audio")

    root.mainloop()


if __name__ == "__main__":
    main()
