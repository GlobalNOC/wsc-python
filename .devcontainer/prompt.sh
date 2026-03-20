__bash_prompt() {
    # switch arrow color to red if exit code is non-zero
    __bp_arrow() {
    local exit_code=$?
    [[ $exit_code -ne 0 ]] && echo -n $'\033[1;31m➜\033[0m' || echo -n "➜"

    # preserve exit_code
    return $exit_code
    }

    # display error code if non-zero in red
    __bp_error() {
    local exit_code=$?
    [[ $exit_code -ne 0 ]] && echo -n $'\033[1;31m'"[$exit_code]"$'\033[0m '

    # preserve exit_code
    return $exit_code
    }

    # display the git branch in yellow if one exists
    __bp_git() {
    local branch=$(git --no-optional-locks symbolic-ref --short HEAD 2>/dev/null || git --no-optional-locks rev-parse --short HEAD 2>/dev/null)
    [[ -n "$branch" ]] && echo -n $'\033[33m'" (${branch})"$'\033[0m'
    }

    # Username in green
    local username="\[\033[32m\]\u\[\033[0m\]"

    # Current path in blue
    local path="\[\033[1;34m\]\w\[\033[0m\]"

    # create full prompt
    PS1="\$(__bp_error)${username} \$(__bp_arrow) ${path}\$(__bp_git)\n$ "
    unset -f __bash_prompt
}
__bash_prompt
