//
// Created by Anakin on 2026-11-01.
//

#ifndef ROOT_OPLUS_ACE5_ROOT_STAGE_H
#define ROOT_OPLUS_ACE5_ROOT_STAGE_H

#include <string>

/* Forks a detached child that owns the whole exploit and returns immediately.
 * The child, not this process, ends up holding the dangling pi_blocked_on, so
 * the UI process stays killable and restartable. */
std::string root_stage_start(const char *status_path, const char *libdir);

std::string root_stage_status(const char *status_path);

/* Runs cmd as root through the daemon socket; empty string if unreachable. */
std::string root_exec(const char *cmd);

bool root_daemon_alive(std::string *banner);

#endif //ROOT_OPLUS_ACE5_ROOT_STAGE_H
