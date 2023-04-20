import sys
import datetime
import pandas as pd
import subprocess

from os import listdir
from os.path import isfile, join

# directory that includes the collected netflow
netflow_dir: str = '/home/max/WORK/ipd-implementation/netflow/mini'
file_start: str = 'preprocessed_'

files: list = [f for f in listdir(netflow_dir) if isfile(join(netflow_dir, f))]  # netflow files
files: list = sorted(files)

# columns of the collected netflow tables
netflow_columns = ['tag', 'peer_src_ip', 'in_iface', 'out_iface', 'src_ip', 'dst_net', 'src_port', 'dst_port', 'proto',
                   '__', '_', 'ts_start', 'ts_end', 'pkts', 'bytes']

netflow_file_name: str = 'netflow_range_'  # file name of one netflow range
first: bool = True  # identifies if we start a new file
netflow_range_df: pd.DataFrame = pd.DataFrame(columns=netflow_columns)  # will include the data of one netflow range


def add_range_data(date: str, netflow_range_df: pd.DataFrame) -> pd.DataFrame:
    '''reads the data from a gzip csv file and appends it to a given DataFrame'''
    netflow: pd.DataFrame = pd.read_csv(
        f'{netflow_dir}/{file_start}{date}.csv.gz',
        compression='gzip',
        header=0,
        sep=','
    )
    return pd.concat([netflow_range_df, netflow], ignore_index=True)


def collect_running(finish: int):
    tmp_range: str = '/home/max/WORK/ipd-implementation/netflow/RUNNNING_netflow.csv.gz'

    if isfile(tmp_range):
        range_df: pd.DataFrame = pd.read_csv(
            tmp_range,
            compression='gzip',
            sep=','
        )
    else:
        range_df: pd.DataFrame = pd.DataFrame(columns=netflow_columns)

    for i in range(len(files)):
        file: str = files[i]

        # check if we have a file of the netflow collector
        if 'preprocessed_' in file:
            # read the netflow and add it to full frame
            netflow: pd.DataFrame = pd.read_csv(
                f'{netflow_dir}/{file}',
                compression='gzip',
                header=0,
                sep=','
            )
            range_df = pd.concat([range_df, netflow], ignore_index=True)

    # if the netflow collector has finshed name the file correctly with ending of the time of ending
    if finish == '1':
        time: str = datetime.datetime.now().strftime("%d%M%Y_%H%M%S")
        range_df.to_csv(
            f'{netflow_dir}/../COLLECTED_{time}.csv.gz',
            compression='gzip',
            index=False,
        )
        subprocess.run(f'rm {tmp_range}', shell=True)
    else:  # we are not finished --> save data to csv to later append netflow
        range_df.to_csv(
            tmp_range,
            compression='gzip',
            index=False,
        )


def main():
    for i in range(len(files)):
        file: str = files[i]

        # check if we have a file of the netflow collector
        if 'preprocessed_' in file:
            date: str = file.split('_')[1].split('.')[0]  # YYYYMMTThhmm
            act: datetime.datetime = datetime.datetime.strptime(f'{date}', '%Y%m%d%H%M')

            # check if we start a new file
            if first:
                netflow_file_name += date + '_'  # append
                first: bool = False  # set bool to flag that new range has started

            # check if we have not reached end of file list
            if i+1 < len(files):
                # check if next_date is one minute after the actual time
                next_date: str = files[i+1].split('_')[1].split('.')[0]
                next_d: datetime.datetime = datetime.datetime.strptime(f'{next_date}', '%Y%m%d%H%M')
                print(next_d)

                diff: int = int(divmod((next_d - act).total_seconds(), 60)[0])  # minutes till next flow

                if diff == 1:
                    # next netflow file will also be added -> add this file without postprocessing
                    netflow_range_df: pd.DataFrame = add_range_data(date, netflow_range_df)
                else:  # last date for this range
                    netflow_file_name += date  # append last date of range
                    netflow_range_df: pd.DataFrame = add_range_data(date, netflow_range_df)  # append data
                    # save netflow data to csv with compression
                    netflow_range_df.to_csv(
                        f'{netflow_dir}/../{netflow_file_name}.csv.gz',
                        index=False,
                        compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
                    )

                    # reset filename, netflow dataframe and first flag
                    netflow_file_name: str = 'netflow_range_'
                    netflow_range_df: pd.DataFrame = pd.DataFrame(columns=netflow_columns)
                    first: bool = True  # next netflow file will start a new netflow range
            else:  # reached end of file list
                netflow_file_name += date  # append last date of range
                netflow_range_df: pd.DataFrame = add_range_data(date, netflow_range_df)  # add date
                # save netflow range to csv with compression
                netflow_range_df.to_csv(
                    f'{netflow_dir}/../{netflow_file_name}.csv.gz',
                    index=False,
                    compression={'method': 'gzip', 'compresslevel': 1, 'mtime': 1}
                )


if __name__ == '__main__':
    try:
        finish: int = sys.argv[1]  # 1 if last collection or 0 if still collecting --> error when not in running proc
        collect_running(finish)
    except Exception as e:  # run normal mode
        main()
