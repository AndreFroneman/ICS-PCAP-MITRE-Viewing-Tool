import { describe, expect, it } from 'vitest';
import { reviewCapture } from '../src/lib/review.ts';
import type { Row } from '../src/lib/model.ts';
const packet=(fields:Partial<Row>)=>({n:1,src:'10.0.0.1',dst:'10.0.0.2',...fields}) as Row;
describe('Passive review claims',()=>{
 it('does not infer weakness from read-only Modbus or TLS',()=>{expect(reviewCapture([packet({modbusFunc:3}),packet({proto:'TLS'})])).toEqual([]);});
 it('retains write evidence without claiming exploitation or a CVE',()=>{const [w]=reviewCapture([packet({modbusFunc:16})]);expect(w.packets).toEqual([1]);expect(w.fr).toEqual([2,3,5]);expect(w.detail).toContain('authorised maintenance');});
 it('never includes credential values in review exports',()=>{const out=JSON.stringify(reviewCapture([packet({mqttPass:'private-example-secret'})]));expect(out).not.toContain('private-example-secret');expect(out).toContain('credentials');});
});
