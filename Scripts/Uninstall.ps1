rm "$(r2 -H R2_USER_PLUGINS)\\reai_radare.dll"
rm "$(r2 -H R2_USER_PLUGINS)\\reai_radare.lib"
Remove-Item -Recurse -Force  "~\\.local\\RevEngAI\\Radare2"
