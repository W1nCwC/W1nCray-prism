// Copyright (C) 2023  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>

// This file is an addition of the Prism patch set, see PRISM-PATCHES.md.

package protocol

// DefaultReplayCacheEntries is the upstream capacity of each of the two
// process-wide replay caches (stream and packet).
const DefaultReplayCacheEntries = 4 * 1024 * 1024

// SetReplayCacheCapacity sets the capacity of the stream and the packet
// replay cache. It is safe for concurrent use and may be called at any time,
// normally before the first listener starts. A value of 0 or less leaves that
// cache unchanged. Changing a capacity drops the signatures stored so far.
// Neither the wire format nor any protocol behavior depends on the capacity.
func SetReplayCacheCapacity(streamEntries, packetEntries int) {
	if streamEntries > 0 {
		streamReplayCache.SetCapacity(streamEntries)
	}
	if packetEntries > 0 {
		packetReplayCache.SetCapacity(packetEntries)
	}
}
