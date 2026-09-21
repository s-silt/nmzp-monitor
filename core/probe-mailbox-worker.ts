import {readMailbox} from './probe-mailbox.ts';
process.stdout.write(JSON.stringify(readMailbox(process.argv[2]??'')));
