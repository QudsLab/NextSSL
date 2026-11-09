# KAT provenance: chaskey

Expected tags: the `vectors[64][8]` table inside the author's own reference file chaskey12.c (Nicky Mouha, https://mouha.be/wp-content/uploads/chaskey12.c, sha256 a5833a78d08b4c035e4c567a2e8124b8585df7508df893b4ec02c935d8e25f00, fetched 2026-11-08): key 00 11 22 .. ff, message 00 01 .. (n-1), n = 0..63, first 8 bytes of the tag. Extracted by script. Tags longer than 8 bytes are the same computation with more bytes copied out; the glue test checks that the 8-byte tag is a prefix of the 16-byte tag.
