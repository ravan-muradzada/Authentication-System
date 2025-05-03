import { PrismaClient } from '@prisma/client';
import chalk from 'chalk';

const prisma = new PrismaClient();

prisma.$connect()
    .then(() => console.log(chalk.blue.bold('✅ Prisma connected')))
    .catch(err => {
        console.error(chalk.red.bold('❌ Prisma connection error:'), err);
        process.exit(1);
    });

export default prisma;
