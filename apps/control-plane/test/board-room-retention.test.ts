import { env } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

function event(sessionId: string, index: number) {
  return {
    eventId: `bevt_quiet_retention_${index.toString().padStart(8, "0")}`,
    sessionId,
    type: "message.updated",
    recordId: `msg_quiet_retention_${index.toString().padStart(8, "0")}`,
    revision: 1,
  };
}

describe.sequential("BoardRoom quiet retention", () => {
  it("compacts an expired quiet room without requiring another publish", async () => {
    const sessionId = "csess_quiet_retention01";
    const room = env.BOARD_ROOMS.getByName(sessionId);
    await room.publishBatch(Array.from({ length: 32 }, (_, index) => event(sessionId, index)));

    const scheduled = await runInDurableObject(room, async (_instance, state) => ({
      rows: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM fanout_events").one().count,
      alarm: await state.storage.getAlarm(),
    }));
    expect(scheduled.rows).toBe(32);
    expect(scheduled.alarm).not.toBeNull();

    await runInDurableObject(room, async (_instance, state) => {
      state.storage.sql.exec("UPDATE fanout_events SET expires_at=?", new Date(Date.now() - 1_000).toISOString());
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(room)).toBe(true);

    const compacted = await runInDurableObject(room, async (_instance, state) => ({
      rows: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM fanout_events").one().count,
      alarm: await state.storage.getAlarm(),
    }));
    expect(compacted).toEqual({ rows: 0, alarm: null });
  });

  it("bounds a publish burst and converges every expired page after the room becomes quiet", async () => {
    const sessionId = "csess_quiet_burst_0001";
    const room = env.BOARD_ROOMS.getByName(sessionId);
    const total = 2_100;
    for (let start = 0; start < total; start += 32) {
      const count = Math.min(32, total - start);
      await room.publishBatch(Array.from({ length: count }, (_, offset) => event(sessionId, start + offset + 10_000)));
    }
    const bounded = await runInDurableObject(room, (_instance, state) => state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM fanout_events").one().count);
    expect(bounded).toBeLessThanOrEqual(2_048);

    await runInDurableObject(room, async (_instance, state) => {
      state.storage.sql.exec("UPDATE fanout_events SET expires_at=?", new Date(Date.now() - 1_000).toISOString());
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    expect(await runDurableObjectAlarm(room)).toBe(true);
    let alarms = 1;
    while (true) {
      const remaining = await runInDurableObject(room, async (instance, state) => {
        const rows = state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM fanout_events").one().count;
        if (rows > 0) await instance.alarm();
        return rows;
      });
      if (remaining === 0) break;
      alarms += 1;
      if (alarms > 16) throw new Error("BoardRoom retention did not converge");
    }
    const final = await runInDurableObject(room, async (_instance, state) => ({
      rows: state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM fanout_events").one().count,
      alarm: await state.storage.getAlarm(),
    }));
    expect(final).toEqual({ rows: 0, alarm: null });
    expect(alarms).toBeGreaterThan(1);
    expect(alarms).toBeLessThanOrEqual(Math.ceil(bounded / 250));
    console.log(`CONDUIT_BOARD_ROOM_RETENTION=${JSON.stringify({ burstRows: total, retainedBound: bounded, deletePage: 250, alarmInvocations: alarms, finalRows: final.rows })}`);
  });
});
