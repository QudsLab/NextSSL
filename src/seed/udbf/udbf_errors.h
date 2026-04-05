/* udbf_errors.h — UDBF Error Code Definitions (Plan 404 TIER 3)
 *
 * Error codes returned by seed_udbf_feed(), seed_udbf_read().
 */
#ifndef SEED_UDBF_ERRORS_H
#define SEED_UDBF_ERRORS_H

/* -------------------------------------------------------------------------
 * udbf_result_t — UDBF operation result codes
 * -------------------------------------------------------------------------*/
typedef enum {
    UDBF_OK = 0,                    /* Success */
    UDBF_ERR_ALREADY_LOADED = -1,   /* Feed called when data already loaded */
    UDBF_ERR_NO_DATA = -2,          /* Read / wipe called with no data loaded */
    UDBF_ERR_LABEL_NOT_FOUND = -3,  /* Requested label not present in UDBF */
    UDBF_ERR_TOO_LARGE = -4,        /* Input too large (> 1 MB) or value too small */
} udbf_result_t;

#endif /* SEED_UDBF_ERRORS_H */
