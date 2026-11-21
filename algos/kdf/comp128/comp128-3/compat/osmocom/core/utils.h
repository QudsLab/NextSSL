/* ours: replaces libosmocore's core/utils.h (talloc, backtrace, panic ...) for the wired files; only OSMO_ASSERT is used. */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define OSMO_ASSERT(exp) do { if (!(exp)) abort(); } while (0)
