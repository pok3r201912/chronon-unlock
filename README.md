Chronon Unlock - Quantum Break Cinematic Unlock
===============================================

Version: 1.0.0
Platform: Steam, Windows x64

Removes the hard 30 FPS cap on in-engine (Northlight) cutscenes so they
run at your normal framerate. Timeline timing and audio are left alone.
Pre-rendered Bink videos are unchanged.


REQUIREMENTS
------------
You need one of the following:

  A) Ultimate ASI Loader
     - Place d3d11.dll in the game's dx11 folder
       (QuantumBreak\dx11 next to QuantumBreak.exe)

  B) OptiScaler (recommended if ASI Loader refuses to launch)
     - Set LoadASI=true in OptiScaler's config
     - You will put the .asi in OptiScaler\plugins instead


INSTALLATION
------------
1. Extract this archive.

2. Copy QuantumBreakCinematicUnlock.asi:

   - ASI Loader path:
       QuantumBreak\dx11\QuantumBreakCinematicUnlock.asi

   - OptiScaler path:
       (your OptiScaler folder)\plugins\QuantumBreakCinematicUnlock.asi

3. Launch the game through Steam.


VERIFICATION
------------
After launching once, open the log next to the ASI:

  QuantumBreakCinematicUnlock.log

Success looks like:

  [ChrononUnlock] ... | ASI plugin loaded.
  [ChrononUnlock] ... | signatures resolved; patches at ...
  [ChrononUnlock] ... | ASI plugin is active. In-engine cinematics are uncapped.

If you see "cinematic signatures not found" or a timeout, the EXE
layout may differ from what was tested. Post the full log on the
mod page.


NOTES
-----
- Steam Windows x64 only.
- Signature-based: no fixed SHA-256 lock to a single game build.
- Only affects in-engine cinematics. Bink/FMV videos stay at their
  original framerate.
- Safe to remove: delete the .asi (and optionally the .log).


TROUBLESHOOTING
---------------
Game won't start with Ultimate ASI Loader:
  Use OptiScaler with LoadASI=true instead (see Requirements).

Log says plugin loaded but cutscenes still feel capped:
  Confirm the log shows "ASI plugin is active". Check that you are
  looking at an in-engine cutscene, not a Bink video.

Antivirus flags the ASI:
  False positives on small native plugins are common. The file only
  patches local game memory; it does not connect to the internet.


CREDITS
-------
Signature-scanning rewrite for broader Steam build compatibility.
Based on earlier Quantum Break cinematic unlock research and plugins
by the community.


PERMISSIONS
-----------
See the mod page on Nexus Mods for reuse and redistribution rules.