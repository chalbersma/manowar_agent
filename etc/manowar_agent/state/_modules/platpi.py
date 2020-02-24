#!/usr/bin/env python3

"""
Caller for the Platform Private Investigator

:maintainer: Chris Halbersma <chris@halbersma.us>
:maturity: new
:platform: We'll see

Meant to give a "best guess for a platform. P
"""

import logging

__virtualname__ = "platpi"

def __virtual__():


    return __virtualname__

def guess(*opts, **kwargs):

    """
    Guess the Platform I'm Running On
    """

    logger = logging.getLogger(__name__)

    value = {"current_guess" : "None"}

    try:
        import saltcell.mow_platform
    except ImportError as ImportError_Abs:
        logger.error("Unable to Load saltcell.mow_platform from Path Attempting Relative Load")
        logger.debug("Attempting to Relative Path Load.")
        logger.debug("Error: {}".format(ImportError_Abs))
    except Exception as Unknown_Error:
        logger.error("Unknown_Error")
        logger.debug("Error: {}".format(Unknown_Error))
        value["error"] = True

    if "error" in value.keys():
        # Overwrite Error with New Hotness
        value = saltcell.mow_platform.guess()
    else:
        logger.debug("Error in Import Ignore Run")

    return value
