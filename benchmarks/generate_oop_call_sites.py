#!/usr/bin/env python3
"""Generate a deterministic OOP call-site workload for compiler measurements."""
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--calls", type=int, default=400)
    args = parser.parse_args()
    if args.calls < 1:
        parser.error("--calls must be positive")
    source = """class Only
  function value() returns int
    return 3
  end function
end class

function work(receiver)
  total = 0
"""
    source += "  total += receiver.value()\n" * args.calls
    source += f"""  return total
end function

function main(args)
  if work(Only()) != {3 * args.calls} then return 1 end if
  print "[OK]"
  return 0
end function
"""
    args.output.write_text(source, encoding="utf-8")

if __name__ == "__main__":
    main()
