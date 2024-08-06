import { Table, ConfigProvider, Pagination } from 'antd';
import { useStyles } from './index.style.ts';
import { IPSubmissionsTableItem } from '@/services/problems/types.ts';
import { useState } from 'react';
const SubmissionsTable = ({
  dataSource,
}: {
  dataSource: IPSubmissionsTableItem[] | undefined;
}) => {
  const pageSize = 10;
  const { styles } = useStyles();
  const [page, setPage] = useState(1);
  const createTableHead = (title: string) => (
    <div className={styles.titleSpanStyle}>{title}</div>
  );
  const columns = [
    {
      title: createTableHead('Task ID'),
      dataIndex: 'id',
      render: (_: any,__: any,index: number) => (index + 1),
    },
    {
      title: createTableHead('Prover Name'),
      dataIndex: 'prover_name',
      key: 'prover_name',
    },
    {
      title: createTableHead('Proof System'),
      dataIndex: 'proof_system',
      key: 'proof_system',
    },
    {
      title: createTableHead('Algorithm'),
      dataIndex: 'algorithm',
      key: 'algorithm',
    },
    {
      title: createTableHead('Setup time（seconds）'),
      width: 190,
      dataIndex: 'setup_time',
      key: 'setup_time',
    },
    {
      title: (
        <div className={styles.TableTitle}>
          <div>Witness generation</div>
          <div>time（seconds）</div>
        </div>
      ),
      width: 180,
      dataIndex: 'witness_generation_time',
      key: 'witness_generation_time',
    },
    {
      title: (
        <div className={styles.TableTitle}>
          <div>Proof generation</div>
          <div>time（seconds）</div>
        </div>
      ),
      width: 200,
      dataIndex: 'proof_generation_time',
      key: 'proof_generation_time',
    },
    {
      title: (
        <div className={styles.TableTitle}>
          <div>Verification</div>
          <div>time（seconds）</div>
        </div>
      ),
      width: 180,
      dataIndex: 'verify_time',
      key: 'verify_time',
    },
    {
      title: createTableHead('Peak memory（MB）'),
      width: 180,
      dataIndex: 'peak_memory',
      key: 'peak_memory',
    },
    {
      title: createTableHead('Proof size（KB）'),
      width: 150,
      dataIndex: 'proof_size',
      key: 'proof_size',
    },
  ];

  return (
    <>
      <ConfigProvider
        theme={{
          components: {
            Table: {
              headerBg: '#fff',
              colorBgContainer:
                'linear-gradient(0deg, rgba(255, 255, 255, 0.50) 0%, rgba(255, 255, 255, 0.50) 100%), #F8F9FA',
              headerSplitColor: 'none',
              cellPaddingBlockMD: 20,
              cellPaddingInlineMD: 12,
              colorText: '#2B332D',
            },
          },
        }}
      >
        <div className={styles.tableBox}>
          <Table
            size="middle"
            pagination={false}
            rowKey={'id'}
            className={styles.tableStyle}
            bordered={false}
            scroll={{ x: 'calc(100% + 50%)' }}
            columns={columns}
            dataSource={
              dataSource?.slice(page * pageSize - pageSize, page * pageSize) ||
              []
            }
          />
        </div>
        {dataSource?.length && (
          <Pagination
            onChange={(page: number) => {
              setPage(page);
            }}
            showSizeChanger={false}
            className={styles.paginationStyle}
            defaultCurrent={1}
            pageSize={pageSize}
            total={dataSource?.length}
          />
        )}
      </ConfigProvider>
    </>
  );
};

export default SubmissionsTable;